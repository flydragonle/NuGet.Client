// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;

#if IS_DESKTOP
using System.Security.Cryptography.Pkcs;
#endif

namespace NuGet.Packaging.Signing
{
    /// <summary>
    /// Package signature information.
    /// </summary>
    public class Signature
    {
#if IS_DESKTOP
        /// <summary>
        /// A SignedCms object holding the signature and SignerInfo.
        /// </summary>
        public SignedCms SignedCms { get; }

        /// <summary>
        /// Indicates if this is an author or repository signature.
        /// </summary>
        public SignatureType Type { get; }

        /// <summary>
        /// Signature content.
        /// </summary>
        public SignatureContent SignatureContent { get; }

        /// <summary>
        /// Signature timestamp.
        /// </summary>
        public Timestamp Timestamp { get; }

        /// <summary>
        /// SignerInfo for this signature.
        /// </summary>
        public SignerInfo SignerInfo => SignedCms.SignerInfos[0];

        private Signature(SignedCms signedCms)
        {
            SignedCms = signedCms ?? throw new ArgumentNullException(nameof(signedCms));
            SignatureContent = SignatureContent.Load(SignedCms.ContentInfo.Content, SigningSpecifications.V1);
            Type = GetSignatureType(SignerInfo);
            Timestamp = GetTimestamp(SignerInfo);
        }

        /// <summary>
        /// Save the signed cms signature to a stream.
        /// </summary>
        /// <param name="stream"></param>
        public void Save(Stream stream)
        {
            using (var ms = new MemoryStream(SignedCms.Encode()))
            {
                ms.CopyTo(stream);
            }
        }

        /// <summary>
        /// Retrieve the bytes of the signed cms signature.
        /// </summary>
        public byte[] GetBytes()
        {
            return SignedCms.Encode();
        }

        /// <summary>
        /// Create a signature based on a valid signed cms
        /// </summary>
        /// <param name="cms">signature data</param>
        public static Signature Load(SignedCms cms)
        {
            if (cms.SignerInfos.Count != 1)
            {
                throw new InvalidOperationException(Strings.Error_NotOnePrimarySignature);
            }

            return new Signature(cms);
        }

        /// <summary>
        /// Create a signature based on a valid byte array to be decoded as a signed cms
        /// </summary>
        /// <param name="data">signature data</param>
        public static Signature Load(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var cms = new SignedCms();
            cms.Decode(data);

            return Load(cms);
        }

        /// <summary>
        /// Create a signature based on a valid byte stream to be decoded as a signed cms
        /// </summary>
        /// <param name="stream">signature data</param>
        public static Signature Load(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            using (stream)
            using (var ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                return Load(ms.ToArray());
            }
        }

        /// <summary>
        /// Get Signature type depending on signature metadata
        /// </summary>
        /// <param name="signer">SignerInfo containing signature metadata</param>
        private static SignatureType GetSignatureType(SignerInfo signer)
        {
            // TODO: Change this to use the new attributes that justin is adding.
            return SignatureType.Author;
        }
        private static Timestamp GetTimestamp(SignerInfo signer)
        {
            var authorUnsignedAttributes = signer.UnsignedAttributes;
            var timestampCms = new SignedCms();

            foreach (var attribute in authorUnsignedAttributes)
            {
                if (string.Equals(attribute.Oid.Value, Oids.SignatureTimeStampTokenAttributeOid))
                {
                    timestampCms.Decode(attribute.Values[0].RawData);

                    if (Rfc3161TimestampVerificationUtility.TryReadTSTInfoFromSignedCms(timestampCms, out var tstInfo))
                    {
                        const long TicksPerMicrosecond = 10;

                        var accuracy = tstInfo.AccuracyInMicroseconds;
                        var accuracyTimeSpan = TimeSpan.Zero;
                        if (accuracy != null)
                        {
                            accuracyTimeSpan = TimeSpan.FromTicks(accuracy.Value * TicksPerMicrosecond);
                        }

                        return new Timestamp(timestampCms.SignerInfos[0],
                                             upperLimit: tstInfo.Timestamp.Add(accuracyTimeSpan),
                                             lowerLimit: tstInfo.Timestamp.Subtract(accuracyTimeSpan));
                    }
                }
            }
            return null;
        }

#else
        /// <summary>
        /// Retrieve the bytes of the signed cms signature.
        /// </summary>
        public byte[] GetBytes()
        {
            throw new NotSupportedException();
        }
#endif
    }
}