﻿/*
 * Copyright 2014 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using SelfHost.AspId;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Contexts;
using System.Web;
using Abp.Dependency;
using Thinktecture.IdentityManager;
using Thinktecture.IdentityManager.AspNetIdentity;
using Thinktecture.IdentityManager.Configuration;
using ZKJL.Identity.Core.Authorization;
using ZKJL.Identity.Core.Users;
using IdentityDbContext = ZKJL.Identity.EntityFramework.EntityFramework.IdentityDbContext;

namespace SelfHost.IdMgr
{
    public static class SimpleIdentityManagerServiceExtensions
    {
        public static void ConfigureSimpleIdentityManagerService(this IdentityManagerServiceFactory factory)
        {
            //factory.Register(new Registration<IdentityDbContext>(resolver => new IdentityDbContext(connectionString)));
            //factory.Register(new Registration<UserStore>());
            //factory.Register(new Registration<RoleStore>());
            //factory.Register(new Registration<UserManager>());
            //factory.Register(new Registration<RoleManager>());
            factory.Register(new Registration<UserManager>(resolver => IocManager.Instance.Resolve<UserManager>()));
            factory.Register(new Registration<RoleManager>(resolver => IocManager.Instance.Resolve<RoleManager>()));
            factory.IdentityManagerService = new Registration<IIdentityManagerService, SimpleIdentityManagerService>();
        }
    }

    public class SimpleIdentityManagerService : AspNetIdentityManagerService<User, long, Role, int>
    {
        public SimpleIdentityManagerService(UserManager userMgr, RoleManager roleMgr)
            : base(userMgr, roleMgr)
        {
        }
    }
}