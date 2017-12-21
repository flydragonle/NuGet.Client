// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
#if IS_DESKTOP
using System.Security.Cryptography.Pkcs;
#endif
using System.Security.Cryptography.X509Certificates;
using NuGet.Common;

namespace NuGet.Packaging.Signing
{
    /// <summary>
    /// Utility methods for signing.
    /// </summary>
    public static class SigningUtility
    {
        public static void VerifyCertificate(X509Certificate2 certificate)
        {
            if (!IsSignatureAlgorithmSupported(certificate))
            {
                throw new SignatureException(NuGetLogCode.NU3022, Strings.SigningCertificateHasUnsupportedSignatureAlgorithm);
            }

            if (!IsCertificatePublicKeyValid(certificate))
            {
                throw new SignatureException(NuGetLogCode.NU3023, Strings.SigningCertificateFailsPublicKeyLengthRequirement);
            }

            if (IsCertificateValidityPeriodInTheFuture(certificate))
            {
                throw new SignatureException(NuGetLogCode.NU3024, Strings.SignatureNotYetValid);
            }

            if (HasExtendedKeyUsage(certificate, Oids.LifetimeSignerEkuOid))
            {
                throw new SignatureException(NuGetLogCode.NU3025, Strings.ErrorCertificateHasLifetimeSignerEKU);
            }
        }
        /// <summary>
        /// Determines if a certificate's signature algorithm is supported.
        /// </summary>
        /// <param name="certificate">Certificate to validate</param>
        /// <returns>True if the certificate's signature algorithm is supported.</returns>
        public static bool IsSignatureAlgorithmSupported(X509Certificate2 certificate)
        {
            switch (certificate.SignatureAlgorithm.Value)
            {
                case Oids.Sha256WithRSAEncryption:
                case Oids.Sha384WithRSAEncryption:
                case Oids.Sha512WithRSAEncryption:
                    return true;

                default:
                    return false;
            }
        }


        /// <summary> 
        /// Validates the public key requirements for a certificate 
        /// </summary> 
        /// <param name="certificate">Certificate to validate</param> 
        /// <returns>True if the certificate's public key is valid within NuGet signature requirements</returns> 
        public static bool IsCertificatePublicKeyValid(X509Certificate2 certificate)
        {
            // Check if the public key is RSA with a valid keysize 
            var RSAPublicKey = RSACertificateExtensions.GetRSAPublicKey(certificate);

            if (RSAPublicKey != null)
            {
                return RSAPublicKey.KeySize >= SigningSpecifications.V1.RSAPublicKeyMinLength;
            }

            return false;
        }

        /// <summary>
        /// Validates if the certificate contains the lifetime signing EKU
        /// </summary>
        /// <param name="certificate">Certificate to validate</param>
        /// <returns>True if the certificate has the lifetime signing EKU</returns>
        public static bool HasLifetimeSigningEku(X509Certificate2 certificate)
        {
            return SigningUtility.HasExtendedKeyUsage(certificate, Oids.LifetimeSignerEkuOid);
        }

        /// <summary>
        /// Create an ordered list of certificates. The leaf node is returned first.
        /// </summary>
        /// <remarks>This does not check validity or trust. It returns the chain as-is.</remarks>
        public static IReadOnlyList<X509Certificate2> CertificateChainToList(X509Chain certChain)
        {
            if (certChain == null)
            {
                throw new ArgumentNullException(nameof(certChain));
            }

            var certs = new List<X509Certificate2>();

            foreach (var item in certChain.ChainElements)
            {
                certs.Add(item.Certificate);
            }

            return certs;
        }

        /// <summary>
        /// Checks if an X509Certificate2 contains a particular Extended Key Usage (EKU).
        /// </summary>
        /// <param name="certificate">X509Certificate2 to be checked.</param>
        /// <param name="ekuOid">String OID of the Extended Key Usage</param>
        /// <returns>A bool indicating if the X509Certificate2 contains specified OID in its Extended Key Usage.</returns>
        public static bool HasExtendedKeyUsage(X509Certificate2 certificate, string ekuOid)
        {
            foreach (var extension in certificate.Extensions)
            {
                if (string.Equals(extension.Oid.Value, Oids.EnhancedKeyUsageOid))
                {
                    var ekuExtension = (X509EnhancedKeyUsageExtension)extension;

                    foreach (var eku in ekuExtension.EnhancedKeyUsages)
                    {
                        if (eku.Value == ekuOid)
                        {
                            return true;
                        }
                    }

                    break;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks if an X509Certificate2 is valid for a particular purpose.
        /// </summary>
        /// <remarks>
        /// This must not be used in evaluation of a signed package.
        /// A more accurate test is building a chain with the specified EKU asserted in the application policy.
        /// </remarks>
        /// <param name="certificate">X509Certificate2 to be checked.</param>
        /// <param name="ekuOid">String OID of the Extended Key Usage</param>
        /// <returns>A bool indicating if the X509Certificate2 contains specified OID string in its Extended Key Usage.</returns>
        public static bool IsValidForPurposeFast(X509Certificate2 certificate, string ekuOid)
        {
            foreach (var extension in certificate.Extensions)
            {
                if (string.Equals(extension.Oid.Value, Oids.EnhancedKeyUsageOid))
                {
                    var ekuExtension = (X509EnhancedKeyUsageExtension)extension;

                    if (ekuExtension.EnhancedKeyUsages.Count == 0)
                    {
                        return true;
                    }

                    foreach (var eku in ekuExtension.EnhancedKeyUsages)
                    {
                        if (eku.Value == ekuOid)
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }

            return true;
        }

#if IS_DESKTOP
        public static CryptographicAttributeObjectCollection GetSignAttributes(
            SignPackageRequest request,
            IReadOnlyList<X509Certificate2> chainList)
        {
            var attributes = new CryptographicAttributeObjectCollection
            {
                new Pkcs9SigningTime()
            };

            if (request.SignatureType != SignatureType.Unknown)
            {
                // Add signature type if set.
                attributes.Add(AttributeUtility.GetCommitmentTypeIndication(request.SignatureType));
            }

            // Add the full chain of certificate hashes
            attributes.Add(AttributeUtility.GetSigningCertificateV2(chainList, request.SignatureHashAlgorithm));

            return attributes;
        }

        internal static void SetCertBuildChainPolicy(
            X509ChainPolicy policy,
            X509Certificate2Collection additionalCertificates,
            DateTime verificationTime,
            NuGetVerificationCertificateType certificateType,
            NuGetChainBuildingRequestType chainBuildingRequestType)
        {
            // This flags should only be set for verification scenarios, not signing
            if (chainBuildingRequestType == NuGetChainBuildingRequestType.Verification)
            {
                policy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.IgnoreCtlNotTimeValid;
            }

            if (certificateType == NuGetVerificationCertificateType.Signature)
            {
                policy.ApplicationPolicy.Add(new Oid(Oids.CodeSigningEkuOid));
            }
            else if (certificateType == NuGetVerificationCertificateType.Timestamp)
            {
                policy.ApplicationPolicy.Add(new Oid(Oids.TimeStampingEkuOid));
            }

            policy.ExtraStore.AddRange(additionalCertificates);

            policy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            policy.RevocationMode = X509RevocationMode.Online;

            if (certificateType != NuGetVerificationCertificateType.Timestamp)
            {
                policy.VerificationTime = verificationTime;
            }
        }

        public static bool IsCertificateValidityPeriodInTheFuture(X509Certificate2 certificate)
        {
            DateTimeOffset signerCertBegin = DateTime.SpecifyKind(certificate.NotBefore, DateTimeKind.Local);

            return signerCertBegin > DateTimeOffset.Now;
        }

        internal static bool BuildCertificateChain(X509Chain chain, X509Certificate2 certificate, out X509ChainStatus[] status)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var buildSuccess = chain.Build(certificate);
            status = new X509ChainStatus[chain.ChainStatus.Length];
            chain.ChainStatus.CopyTo(status, 0);

            // Check if time is not in the future
            return buildSuccess && !IsCertificateValidityPeriodInTheFuture(certificate);
        }

        internal static bool IsSigningCertificateValid(X509Certificate2 certificate, bool failIfInvalid, List<SignatureLog> issues)
        {
            var isValid = true;

            if (!IsSignatureAlgorithmSupported(certificate))
            {
                issues.Add(SignatureLog.Issue(failIfInvalid, NuGetLogCode.NU3022, Strings.SigningCertificateHasUnsupportedSignatureAlgorithm));
                isValid = false;
            }

            if (IsCertificateValidityPeriodInTheFuture(certificate))
            {
                issues.Add(SignatureLog.Issue(failIfInvalid, NuGetLogCode.NU3024, Strings.SignatureNotYetValid));
                isValid = false;
            }

            if (!IsCertificatePublicKeyValid(certificate))
            {
                issues.Add(SignatureLog.Issue(failIfInvalid, NuGetLogCode.NU3023, Strings.SigningCertificateFailsPublicKeyLengthRequirement));
                isValid = false;
            }

            return isValid;
        }

        internal static bool IsTimestampValid(Timestamp timestamp, byte[] data, bool failIfInvalid, List<SignatureLog> issues, SigningSpecifications spec)
        {
            var isValid = true;
            var signerInfo = timestamp.SignerInfo;

            if (!timestamp.TstInfo.HasMessageHash(data))
            {
                issues.Add(SignatureLog.Issue(failIfInvalid, NuGetLogCode.NU3053, Strings.TimestampFailureInvalidHash));
                isValid = false;
            }

            try
            {
                signerInfo.CheckSignature(verifySignatureOnly: true);
            }
            catch (Exception e)
            {
                issues.Add(SignatureLog.Issue(failIfInvalid, NuGetLogCode.NU3050, Strings.ErrorTimestampVerificationFailed));
                issues.Add(SignatureLog.DebugLog(e.ToString()));
                isValid = false;
            }

            if (!IsSignatureAlgorithmSupported(signerInfo.Certificate))
            {
                issues.Add(SignatureLog.Issue(failIfInvalid, NuGetLogCode.NU3042, Strings.TimestampCertificateHasUnsupportedSignatureAlgorithm));
                isValid = false;
            }

            if (!spec.AllowedHashAlgorithmOids.Contains(signerInfo.DigestAlgorithm.Value))
            {
                issues.Add(SignatureLog.Issue(failIfInvalid, NuGetLogCode.NU3052, Strings.TimestampFailureInvalidHashAlgorithmOid));
                isValid = false;
            }

            if (IsCertificateValidityPeriodInTheFuture(signerInfo.Certificate))
            {
                issues.Add(SignatureLog.Issue(failIfInvalid, NuGetLogCode.NU3044, Strings.TimestampNotYetValid));
                isValid = false;
            }

            if (!IsCertificatePublicKeyValid(signerInfo.Certificate))
            {
                issues.Add(SignatureLog.Issue(failIfInvalid, NuGetLogCode.NU3043, Strings.TimestampCertificateFailsPublicKeyLengthRequirement));
                isValid = false;
            }

            return isValid;
        }

        // Ignore some chain status flags to special case them
        internal const X509ChainStatusFlags NotIgnoredCertificateFlags =
            // To set the not ignored flags we have to turn on all the flags and then manually turn off ignored flags
            (~(X509ChainStatusFlags)0) &                      // Start with all flags
            // These flags are ignored because they are known special cases
            (~X509ChainStatusFlags.NotTimeValid) &
            (~X509ChainStatusFlags.NotTimeNested) &           // Deprecated and therefore ignored.
            (~X509ChainStatusFlags.Revoked) &
            (~X509ChainStatusFlags.RevocationStatusUnknown) &
            (~X509ChainStatusFlags.CtlNotTimeValid) &
            (~X509ChainStatusFlags.OfflineRevocation);

        internal static bool ChainStatusListIncludesStatus(X509ChainStatus[] chainStatuses, X509ChainStatusFlags status, out IReadOnlyList<X509ChainStatus> chainStatus)
        {
            chainStatus = chainStatuses
                .Where(x => (x.Status & status) != 0)
                .ToList();

            if (chainStatus.Any())
            {
                return true;
            }

            return false;
        }

        internal static bool TryGetStatusMessage(X509ChainStatus[] chainStatuses, X509ChainStatusFlags status, out IReadOnlyList<string> messages)
        {
            messages = null;

            if (ChainStatusListIncludesStatus(chainStatuses, status, out var chainStatus))
            {
                messages = chainStatus
                    .Select(x => x.StatusInformation?.Trim())
                    .Where(x => !string.IsNullOrEmpty(x))
                    .Distinct()
                    .OrderBy(x => x)
                    .ToList();

                return true;
            }

            return false;
        }
#endif
    }
}