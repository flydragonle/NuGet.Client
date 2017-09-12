using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Packaging.Core;
using NuGet.ProjectManagement;

namespace NuGet.PackageManagement.UI
{
    internal static class PackagesConfigToPackageReferenceMigrator
    {
        internal static async Task<string> DoUpgradeAsync(
            INuGetUIContext context,
            INuGetUI uiService,
            NuGetProject nuGetProject,
            IEnumerable<NuGetProjectUpgradeDependencyItem> upgradeDependencyItems,
            IEnumerable<PackageIdentity> notFoundPackages,
            bool collapseDependencies,
            IProgress<ProgressDialogData> progress,
            CancellationToken token)
        {
            var dependencyItems = upgradeDependencyItems as IList<NuGetProjectUpgradeDependencyItem> ?? upgradeDependencyItems.ToList();

            // 1. Backup files that will change
            var solutionManager = context.SolutionManager;
            var solutionDirectory = solutionManager.SolutionDirectory;
            var backupPath = Path.Combine(solutionDirectory, "Backup", NuGetProject.GetUniqueNameOrName(nuGetProject));
            Directory.CreateDirectory(backupPath);

            // Backup packages.config
            var msBuildNuGetProject = (MSBuildNuGetProject)nuGetProject;
            var packagesConfigFullPath = msBuildNuGetProject.PackagesConfigNuGetProject.FullPath;
            var packagesConfigFileName = Path.GetFileName(packagesConfigFullPath);
            File.Copy(packagesConfigFullPath, Path.Combine(backupPath, packagesConfigFileName), true);

            // Backup project file
            var msBuildNuGetProjectSystem = msBuildNuGetProject.ProjectSystem;
            var projectFullPath = msBuildNuGetProjectSystem.ProjectFileFullPath;
            var projectFileName = Path.GetFileName(projectFullPath);
            File.Copy(projectFullPath, Path.Combine(backupPath, projectFileName), true);

            // 2. Uninstall all packages currently in packages.config
            var progressData = new ProgressDialogData(Resources.NuGetUpgrade_WaitMessage, Resources.NuGetUpgrade_Progress_Uninstalling);
            progress.Report(progressData);

            // Don't uninstall packages we couldn't find - that will just fail
            var actions = dependencyItems.Select(d => d.Package)
                .Where(p => !notFoundPackages.Contains(p))
                .Select(t => NuGetProjectAction.CreateUninstallProjectAction(t, nuGetProject));

            // TODO: How should we handle a failure in uninstalling a package (unfortunately ExecuteNuGetProjectActionsAsync()
            // doesn't give us any useful information about the failure).
            await context.PackageManager.ExecuteNuGetProjectActionsAsync(nuGetProject, actions, uiService.ProjectContext, CancellationToken.None);

            // If there were packages we didn't uninstall because we couldn't find them, they will still be present in
            // packages.config, so we'll have to delete that file now.
            if (File.Exists(packagesConfigFullPath))
            {
                FileSystemUtility.DeleteFile(packagesConfigFullPath, uiService.ProjectContext);
                msBuildNuGetProjectSystem.RemoveFile(Path.GetFileName(packagesConfigFullPath));
            }
            
            
            // Reload the project, and get a reference to the reloaded project
            var uniqueName = msBuildNuGetProjectSystem.ProjectUniqueName;
            await msBuildNuGetProject.SaveAsync(token);

            //solutionManager.ReloadProject(nuGetProject);
            nuGetProject = await solutionManager.GetNuGetProjectAsync(uniqueName);
            await solutionManager.UpgradeProjectToPackageReferenceAsync(nuGetProject);

            // Ensure we use the updated project for installing, and don't display preview or license acceptance windows.
            context.Projects = new[] { nuGetProject };
            var nuGetUI = (NuGetUI)uiService;
            nuGetUI.Projects = new[] { nuGetProject };
            nuGetUI.DisplayPreviewWindow = false;

            // 4. Install the requested packages
            var ideExecutionContext = uiService.ProjectContext.ExecutionContext as IDEExecutionContext;
            if (ideExecutionContext != null)
            {
                await ideExecutionContext.SaveExpandedNodeStates(solutionManager);
            }

            progressData = new ProgressDialogData(Resources.NuGetUpgrade_WaitMessage, Resources.NuGetUpgrade_Progress_Installing);
            progress.Report(progressData);

            var packagesToInstall = GetPackagesToInstall(dependencyItems, collapseDependencies).ToList();
            foreach (var packageIdentity in packagesToInstall)
            {
                var action = UserAction.CreateInstallAction(packageIdentity.Id, packageIdentity.Version);
                await context.UIActionEngine.PerformActionAsync(uiService, action, CancellationToken.None);
            }

            // If any packages didn't install, manually add them to project.json and let the user deal with it.
            var installedPackages = (await nuGetProject.GetInstalledPackagesAsync(CancellationToken.None)).Select(p => p.PackageIdentity);
            var notInstalledPackages = packagesToInstall.Except(installedPackages).ToList();

            if (ideExecutionContext != null)
            {
                await ideExecutionContext.CollapseAllNodes(solutionManager);
            }

            return backupPath;
        }

        private static IEnumerable<PackageIdentity> GetPackagesToInstall(
            IEnumerable<NuGetProjectUpgradeDependencyItem> upgradeDependencyItems, bool collapseDependencies)
        {
            return
                upgradeDependencyItems.Where(
                    upgradeDependencyItem => !collapseDependencies || !upgradeDependencyItem.DependingPackages.Any())
                    .Select(upgradeDependencyItem => upgradeDependencyItem.Package);
        }
    }
}
