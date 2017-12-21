// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

#if IS_DESKTOP
using System.Security.Cryptography.Pkcs;
#endif

using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;

namespace NuGet.Packaging.Signing
{
    /// <summary>
    /// A provider for RFC 3161 timestamps
    /// https://tools.ietf.org/html/rfc3161
    /// </summary>
    public class Rfc3161TimestampProvider : ITimestampProvider
    {
        // Url to an RFC 3161 timestamp server
        private readonly Uri _timestamperUrl;
        private const int _rfc3161RequestTimeoutSeconds = 10;

        public Rfc3161TimestampProvider(Uri timeStampServerUrl)
        {
#if IS_DESKTOP
            // Uri.UriSchemeHttp and Uri.UriSchemeHttps are not available in netstandard 1.3
            if (!string.Equals(timeStampServerUrl.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) &&
                !string.Equals(timeStampServerUrl.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
            {
                throw new ArgumentException(string.Format(
                    CultureInfo.CurrentCulture,
                    Strings.TimestampFailureInvalidHttpScheme,
                    timeStampServerUrl,
                    nameof(Uri.UriSchemeHttp),
                    nameof(Uri.UriSchemeHttps)));
            }
#endif
            _timestamperUrl = timeStampServerUrl ?? throw new ArgumentNullException(nameof(timeStampServerUrl));
        }


#if IS_DESKTOP

        /// <summary>
        /// Timestamps data present in the TimestampRequest.
        /// </summary>
        public Task<Signature> TimestampSignatureAsync(TimestampRequest request, ILogger logger, CancellationToken token)
        {
            var timestampedSignature = TimestampData(request, logger, token);
            return Task.FromResult(Signature.Load(timestampedSignature));
        }

        /// <summary>
        /// Timestamps data present in the TimestampRequest.
        /// </summary>
        public byte[] TimestampData(TimestampRequest request, ILogger logger, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            // Get the signatureValue from the signerInfo object
            using (var signatureNativeCms = NativeCms.Decode(request.SignatureValue, detached: false))
            {
                var signatureValueHashByteArray = NativeCms.GetSignatureValueHash(
                    request.TimestampHashAlgorithm,
                    signatureNativeCms);

                // Allows us to track the request.
                var nonce = GenerateNonce();
                var rfc3161TimestampRequest = new Rfc3161TimestampRequest(
                    signatureValueHashByteArray,
                    request.TimestampHashAlgorithm.ConvertToSystemSecurityHashAlgorithmName(),
                    nonce: nonce,
                    requestSignerCertificates: true);

                // Request a timestamp
                // The response status need not be checked here as lower level api will throw if the response is invalid
                var timestampToken = rfc3161TimestampRequest.SubmitRequest(
                    _timestamperUrl,
                    TimeSpan.FromSeconds(_rfc3161RequestTimeoutSeconds));

                // ensure response is for this request
                ValidateTimestampResponseNonce(nonce, timestampToken);

                if (!timestampToken.TokenInfo.HasMessageHash(signatureValueHashByteArray))
                {
                    throw new SignatureException(NuGetLogCode.NU3053, Strings.TimestampFailureInvalidHash);
                }

                var timestampCms = timestampToken.AsSignedCms();
                ValidateTimestampCms(request.SigningSpec, timestampCms);

                byte[] timestampByteArray;

                using (var timestampNativeCms = NativeCms.Decode(timestampCms.Encode(), detached: false))
                using (var timestampCertChain = new X509Chain())
                {
                    var policy = timestampCertChain.ChainPolicy;

                    policy.ApplicationPolicy.Add(new Oid(Oids.TimeStampingEkuOid));
                    policy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.IgnoreCtlNotTimeValid;

                    policy.ExtraStore.AddRange(timestampCms.Certificates);

                    policy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    policy.RevocationMode = X509RevocationMode.Online;

                    var timestampSignerCertificate = timestampCms.SignerInfos[0].Certificate;
                    if (DateTime.UtcNow < timestampSignerCertificate.NotBefore)
                    {
                        throw new TimestampException(LogMessage.CreateError(
                            NuGetLogCode.NU3044,
                            string.Format(CultureInfo.CurrentCulture,
                            Strings.TimestampCertificateInvalid,
                            $"{Environment.NewLine}{CertificateUtility.X509Certificate2ToString(timestampSignerCertificate)}")));
                    }

                    if (!timestampCertChain.Build(timestampSignerCertificate))
                    {
                        var messages = timestampCertChain.ChainStatus
                            .ToList()
                            .Select(x => x.StatusInformation?.Trim())
                            .Where(x => !string.IsNullOrEmpty(x))
                            .Distinct()
                            .OrderBy(x => x)
                            .ToList();

                        throw new TimestampException(LogMessage.CreateError(
                            NuGetLogCode.NU3041,
                            string.Format(CultureInfo.CurrentCulture,
                            Strings.TimestampCertificateChainBuildFailure,
                            string.Join(", ", messages))));
                    }

                    // Insert all the certificates into timestampCms
                    InsertTimestampCertChainIntoTimestampCms(timestampCms, timestampCertChain, timestampNativeCms);
                    timestampByteArray = timestampCms.Encode();
                }

                signatureNativeCms.AddTimestamp(timestampByteArray);

                return signatureNativeCms.Encode();
            }
        }

        private static void ValidateTimestampCms(SigningSpecifications spec, SignedCms timestampCms)
        {
            var signerInfo = timestampCms.SignerInfos[0];
            try
            {
                signerInfo.CheckSignature(verifySignatureOnly: true);
            }
            catch
            {
                throw new SignatureException(NuGetLogCode.NU3050, Strings.ErrorTimestampVerificationFailed);
            }

            if (!SigningUtility.IsSignatureAlgorithmSupported(signerInfo.Certificate))
            {
                throw new SignatureException(NuGetLogCode.NU3042, Strings.TimestampCertificateHasUnsupportedSignatureAlgorithm);
            }

            if (!spec.AllowedHashAlgorithmOids.Contains(signerInfo.DigestAlgorithm.Value))
            {
                throw new SignatureException(NuGetLogCode.NU3052, Strings.TimestampFailureInvalidHashAlgorithmOid);
            }

            if (SigningUtility.IsCertificateValidityPeriodInTheFuture(signerInfo.Certificate))
            {
                throw new SignatureException(NuGetLogCode.NU3044, Strings.TimestampNotYetValid);
            }

            if (!SigningUtility.IsCertificatePublicKeyValid(signerInfo.Certificate))
            {
                throw new SignatureException(NuGetLogCode.NU3043, Strings.TimestampCertificateFailsPublicKeyLengthRequirement);
            }
        }

        private static void ValidateTimestampResponseNonce(
                byte[] nonce,
                Rfc3161TimestampToken timestampToken)
        {
            if (!nonce.SequenceEqual(timestampToken.TokenInfo.GetNonce()))
            {
                throw new TimestampException(LogMessage.CreateError(
                    NuGetLogCode.NU3051,
                    Strings.TimestampFailureNonceMismatch));
            }
        }

        private static void InsertTimestampCertChainIntoTimestampCms(
            SignedCms timestampCms,
            X509Chain timstampCertChain,
            NativeCms timestampNativeCms)
        {
            timestampNativeCms.AddCertificates(timstampCertChain.ChainElements
                .Cast<X509ChainElement>()
                .Where(c => !timestampCms.Certificates.Contains(c.Certificate))
                .Select(c => c.Certificate.Export(X509ContentType.Cert)));
        }

        private static byte[] GenerateNonce()
        {
            var nonce = new byte[24];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }

            return nonce;
        }
#else
        /// <summary>
        /// Timestamp a signature.
        /// </summary>
        public Task<Signature> TimestampSignatureAsync(TimestampRequest timestampRequest, ILogger logger, CancellationToken token)
        {
            throw new NotImplementedException();
        }
#endif
    }
}