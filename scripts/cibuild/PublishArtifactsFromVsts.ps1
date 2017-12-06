<#
.SYNOPSIS
Sets build variables during a VSTS build dynamically.

.DESCRIPTION
This script is used to publish all offical nupkgs (from dev and release-* branches) to 
myget feeds.

#>

param
(
    [Parameter(Mandatory=$True, ParameterSetName='PublishToMyGet')]
    [switch]$PublishToMyGet,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToMyGet')]
    [string]$NuGetBuildFeedUrl,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToMyGet')]
    [string]$NuGetBuildSymbolsFeedUrl,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToMyGet')]
    [string]$DotnetCoreFeedUrl,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToMyGet')]
    [string]$DotnetCoreSymbolsFeedUrl,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToMyGet')]
    [string]$NuGetBuildFeedApiKey,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToMyGet')]
    [string]$DotnetCoreFeedApiKey,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToBlobFeed')]
    [switch]$PublishToBlobFeed,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToBlobFeed')]
    [string]$NuGetBlobFeedUrl,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToBlobFeed')]
    [string]$NuGetBlobSymbolsFeedUrl,

    [Parameter(Mandatory=$True, ParameterSetName='PublishToBlobFeed')]
    [string]$NuGetBlobFeedApiKey
)

function Push-Packages {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param(
        [parameter(ValueFromPipeline=$True, Mandatory=$True, Position=0)]
        [string[]] $NupkgFiles,
        [string] $ApiKey,
        [string] $BuildFeed,
        [string] $SymbolSource
    )
    Process 
    {
        foreach ($Nupkg in $NupkgFiles)
        {
            # switch case to check if the nupkg path contains symbols.nupkg
            $Feed = Switch -Wildcard ($Nupkg) 
            {
                "*.symbols.nupkg" { $SymbolSource }
                Default { $BuildFeed }
            }

            $opts = 'push', $Nupkg, $ApiKey, '-Source', $Feed
            
            if ($VerbosePreference) 
            {
                $opts += '-verbosity', 'detailed'
            }

            if ($pscmdlet.ShouldProcess($Nupkg, "push to '${Feed}'")) 
            {
                Write-Output "$NuGetExe $opts"
                & $NuGetExe $opts
                if (-not $?) 
                {
                    Write-Error "Failed to push a package '$Nupkg' to myget feed '${Feed}'. Exit code: ${LASTEXITCODE}"
                }
            }
        }
    }
}

$NupkgsDir = Join-Path $env:BUILD_REPOSITORY_LOCALPATH artifacts\nupkgs
$NuGetExe = Join-Path $env:BUILD_REPOSITORY_LOCALPATH .nuget\nuget.exe

if(Test-Path $NupkgsDir)
{
    Write-Output "Publishing nupkgs from '$Nupkgs'"

    if($PublishToMyGet)
    {
        # Push all nupkgs to the nuget-build feed on myget.
        Get-Item "$NupkgsDir\*.nupkg"  | Push-Packages -ApiKey $NuGetBuildFeedApiKey -BuildFeed $NuGetBuildFeedUrl -SymbolSource $NuGetBuildSymbolsFeedUrl
        # We push NuGet.Build.Tasks.Pack nupkg to dotnet-core feed as per the request of the CLI team.
        Get-Item "$NupkgsDir\NuGet.Build.Tasks.Pack*.nupkg" | Push-ToMyGet -ApiKey $DotnetCoreFeedApiKey -BuildFeed $DotnetCoreFeedUrl -SymbolSource $DotnetCoreSymbolsFeedUrl
    }

    if($PublishToBlobFeed)
    {
        # Push all nupkgs to the blob feed on azure.
        Get-Item "$NupkgsDir\*.nupkg"  | Push-Packages -ApiKey $NuGetBlobFeedApiKey -BuildFeed $NuGetBlobFeedUrl -SymbolSource $NuGetBlobFeedUrl
    }
}

