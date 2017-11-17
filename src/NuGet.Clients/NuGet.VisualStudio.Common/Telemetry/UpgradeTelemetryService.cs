// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using Microsoft;
using NuGet.ProjectManagement;
using NuGet.VisualStudio.Telemetry;

namespace NuGet.VisualStudio
{
    public class UpgradeTelemetryService
    {
        protected readonly ITelemetrySession _telemetrySession;

        public static UpgradeTelemetryService Instance =
            new UpgradeTelemetryService(TelemetrySession.Instance);

        public UpgradeTelemetryService(ITelemetrySession telemetrySession)
        {
            Assumes.Present(telemetrySession);

            _telemetrySession = telemetrySession;
        }

        public void EmitUpgradeEvent(ActionEventBase telemetryData)
        {
            if (telemetryData == null)
            {
                throw new ArgumentNullException(nameof(telemetryData));
            }

            var telemetryEvent = new TelemetryEvent(
                TelemetryConstants.UpgradeEventName,
                new Dictionary<string, object>
                {
                    { TelemetryConstants.OperationIdPropertyName, telemetryData.OperationId },
                    { TelemetryConstants.ProjectIdsPropertyName, string.Join(",", telemetryData.ProjectIds) },
                    { TelemetryConstants.PackagesCountPropertyName, telemetryData.PackagesCount },
                    { TelemetryConstants.OperationStatusPropertyName, telemetryData.Status },
                    { TelemetryConstants.StartTimePropertyName, telemetryData.StartTime.ToString() },
                    { TelemetryConstants.EndTimePropertyName, telemetryData.EndTime.ToString() },
                    { TelemetryConstants.DurationPropertyName, telemetryData.Duration },
                    { TelemetryConstants.ProjectsCountPropertyName, telemetryData.ProjectsCount }
                }
            );

            _telemetrySession.PostEvent(telemetryEvent);
        }
    }
}
