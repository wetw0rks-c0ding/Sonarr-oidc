using FluentMigrator;
using NzbDrone.Core.Datastore.Migration.Framework;

namespace NzbDrone.Core.Datastore.Migration
{
    [Migration(239)]
    public class oidc_password_nullable : NzbDroneMigrationBase
    {
        protected override void MainDbUpgrade()
        {
            Alter.Column("Password").OnTable("Users").AsString().Nullable();
            Alter.Column("Salt").OnTable("Users").AsString().Nullable();
        }
    }
}
