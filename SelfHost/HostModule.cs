using System.Reflection;
using Abp.Modules;
using Abp.Zero;
using Abp.Zero.EntityFramework;
using ZKJL.Identity.Core;
using ZKJL.Identity.EntityFramework;

namespace SelfHost
{
    [DependsOn(typeof(IdentityDataModule))]
    public class IdentityApplicationModule : AbpModule
    {
        public override void Initialize()
        {
            IocManager.RegisterAssemblyByConvention(Assembly.GetExecutingAssembly());
        }
    }
}
