// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using FluentAssertions;
using NuGet.Test.Utility;
using Test.Utility.Signing;
using Xunit;

namespace NuGet.CommandLine.FuncTest.Commands
{
    /// <summary>
    /// Tests Sign command
    /// These tests require admin privilege as the certs need to be added to the root store location
    /// </summary>
    [Collection("Sign Command Test Collection")]
    public class VerifyCommandTests
    {
        private const string _noTimestamperWarningCode = "NU3550";
        private const string _primarySignatureInvalidErrorCode = "NU3030";
        private const string _signingDefaultErrorCode = "NU3000";

        private SignCommandTestFixture _testFixture;
        private TrustedTestCert<TestCertificate> _trustedTestCert;
        private string _nugetExePath;
        private string _timestamper;

        public VerifyCommandTests(SignCommandTestFixture fixture)
        {
            _testFixture = fixture ?? throw new ArgumentNullException(nameof(fixture));
            _trustedTestCert = _testFixture.TrustedTestCertificate;
            _nugetExePath = _testFixture.NuGetExePath;
            _timestamper = _testFixture.Timestamper;
        }

        [CIOnlyFact]
        public void VerifyCommand_VerifySignedPackageSucceeds()
        {
            // Arrange
            var testLogger = new TestLogger();

            using (var dir = TestDirectory.Create())
            using (var zipStream = new SimpleTestPackageContext().CreateAsStream())
            {
                var packagePath = Path.Combine(dir, Guid.NewGuid().ToString());

                zipStream.Seek(offset: 0, loc: SeekOrigin.Begin);

                using (var fileStream = File.OpenWrite(packagePath))
                {
                    zipStream.CopyTo(fileStream);
                }

                var signResult = CommandRunner.Run(
                    _nugetExePath,
                    dir,
                    $"sign {packagePath} -CertificateFingerprint {_trustedTestCert.Source.Cert.Thumbprint} -CertificateStoreName {_trustedTestCert.StoreName} -CertificateStoreLocation {_trustedTestCert.StoreLocation}",
                    waitForExit: true);

                signResult.Success.Should().BeTrue();

                // Act
                var verifyResult = CommandRunner.Run(
                    _nugetExePath,
                    dir,
                    $"verify {packagePath} -Signatures",
                    waitForExit: true);

                // Assert
                verifyResult.Success.Should().BeTrue();
                verifyResult.AllOutput.Should().Contain(_noTimestamperWarningCode);
            }
        }

        [CIOnlyFact]
        public void VerifyCommand_VerifySignedAndTimestampedPackageSucceeds()
        {
            // Arrange
            var testLogger = new TestLogger();

            using (var dir = TestDirectory.Create())
            using (var zipStream = new SimpleTestPackageContext().CreateAsStream())
            {
                var packagePath = Path.Combine(dir, Guid.NewGuid().ToString());

                zipStream.Seek(offset: 0, loc: SeekOrigin.Begin);

                using (var fileStream = File.OpenWrite(packagePath))
                {
                    zipStream.CopyTo(fileStream);
                }

                
                var signResult = CommandRunner.Run(
                    _nugetExePath,
                    dir,
                    $"sign {packagePath} -Timestamper {_testFixture.Timestamper} -CertificateFingerprint {_trustedTestCert.Source.Cert.Thumbprint} -CertificateStoreName {_trustedTestCert.StoreName} -CertificateStoreLocation {_trustedTestCert.StoreLocation}",
                    waitForExit: true);

                signResult.Success.Should().BeTrue();

                // Act
                var verifyResult = CommandRunner.Run(
                    _nugetExePath,
                    dir,
                    $"verify {packagePath} -Signatures",
                    waitForExit: true);

                // Assert
                verifyResult.Success.Should().BeTrue();
                verifyResult.AllOutput.Should().NotContain(_noTimestamperWarningCode);
            }
        }

        [CIOnlyFact]
        public void VerifyCommand_VerifyResignedPackageSucceeds()
        {
            // Arrange
            var testLogger = new TestLogger();

            using (var dir = TestDirectory.Create())
            using (var zipStream = new SimpleTestPackageContext().CreateAsStream())
            {
                var packagePath = Path.Combine(dir, Guid.NewGuid().ToString());

                zipStream.Seek(offset: 0, loc: SeekOrigin.Begin);

                using (var fileStream = File.OpenWrite(packagePath))
                {
                    zipStream.CopyTo(fileStream);
                }

                var firstResult = CommandRunner.Run(
                    _nugetExePath,
                    dir,
                    $"sign {packagePath} -CertificateFingerprint {_trustedTestCert.Source.Cert.Thumbprint} -CertificateStoreName {_trustedTestCert.StoreName} -CertificateStoreLocation {_trustedTestCert.StoreLocation}",
                    waitForExit: true);

                var secondResult = CommandRunner.Run(
                    _nugetExePath,
                    dir,
                    $"sign {packagePath} -CertificateFingerprint {_trustedTestCert.Source.Cert.Thumbprint} -CertificateStoreName {_trustedTestCert.StoreName} -CertificateStoreLocation {_trustedTestCert.StoreLocation} -Overwrite",
                    waitForExit: true);
                
                firstResult.Success.Should().BeTrue();
                secondResult.Success.Should().BeTrue();

                // Act
                var verifyResult = CommandRunner.Run(
                    _nugetExePath,
                    dir,
                    $"verify {packagePath} -Signatures",
                    waitForExit: true);

                // Assert
                verifyResult.Success.Should().BeTrue();
                verifyResult.AllOutput.Should().Contain(_noTimestamperWarningCode);
            }
        }

        [CIOnlyFact]
        public async Task VerifyCommand_VerifyPackageWithExpiredCertificateFails()
        {
            // Arrange
            var testLogger = new TestLogger();
            var nupkg = new SimpleTestPackageContext();
            var expiredCert = _testFixture.TrustedTestCertificateExpired;

            using (var dir = TestDirectory.Create())
            {
                var signedPackagePath = await SignedArchiveTestUtility.CreateSignedPackageAsync(expiredCert.Source.Cert, nupkg, dir);

                // Act
                var verifyResult = CommandRunner.Run(
                    _nugetExePath,
                    dir,
                    $"verify {signedPackagePath} -Signatures",
                    waitForExit: true);

                // Assert
                verifyResult.Success.Should().BeFalse();
                verifyResult.AllOutput.Should().Contain(_noTimestamperWarningCode);
                verifyResult.AllOutput.Should().Contain(_primarySignatureInvalidErrorCode);
            }
        }
    }
}