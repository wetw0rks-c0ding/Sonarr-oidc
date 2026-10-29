# Controller permission inventory (RBAC phase 1)

Classification per spec §7. Only the Admin bucket is annotated in this commit;
other buckets are documented here for maintainer sign-off before annotation.

## Admin (annotated this commit)
- V3 Config/* concrete controllers (DownloadClientConfig, HostConfig, ImportListConfig, IndexerConfig, MediaManagementConfig, NamingConfig, UiConfig)
- V3 System: SystemController, BackupController, TaskController
- V5 System: SystemController, BackupController, TaskController
- V5 Settings: GeneralSettingsController

## Read (UI.Read) — pending
All GET/read controllers not in other buckets (Calendar, DiskSpace, Episodes, Health, History, Localization, Logs, MediaCovers, Parse, Statistics, Wanted/*, etc.)

## AddSearch (UI.Add) — pending
Series add/import/lookup, ManualImport, SeriesImport, Release search/push.

## Manage (UI.Manage) — pending
Queue*, CommandController, profiles/*, indexers/*, notifications, download clients, import lists, tags, custom formats, auto-tagging, custom filters, remote path mappings, root folders, season pass, quality definitions.

## Notes
- Abstract base controllers (ConfigController, SettingsController, LogFileControllerBase, EpisodeControllerWithSignalR, ProviderControllerBase, ReleaseControllerBase) are left unannotated; concrete derived controllers carry the attribute.
- X-Api-Key bypass: PermissionAuthorizationHandler succeeds when no role claim and no oidc_sub claim, so automation is unaffected.
