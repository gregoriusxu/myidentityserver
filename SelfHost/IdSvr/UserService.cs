/*
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

using SelfHost.AspId;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Abp.Authorization.Users;
using Abp.Dependency;
using Microsoft.AspNet.Identity;
using Thinktecture.IdentityServer.AspNetIdentity;
using Thinktecture.IdentityServer.Core.Configuration;
using Thinktecture.IdentityServer.Core.Extensions;
using Thinktecture.IdentityServer.Core.Models;
using Thinktecture.IdentityServer.Core.Services;
using ZKJL.Identity.Core.Authorization;
using ZKJL.Identity.Core.Users;
using IdentityDbContext = ZKJL.Identity.EntityFramework.EntityFramework.IdentityDbContext;

namespace SelfHost.IdSvr
{
    public static class UserServiceExtensions
    {
        public static void ConfigureUserService(this IdentityServerServiceFactory factory)
        {
            //factory.Register(new Registration<IdentityDbContext>(resolver => new IdentityDbContext(connString)));
            factory.Register(new Registration<UserManager>(resolver => IocManager.Instance.Resolve<UserManager>()));
            factory.Register(new Registration<RoleManager>(resolver => IocManager.Instance.Resolve<RoleManager>()));
            factory.UserService = new Registration<IUserService, UserService>();
            //factory.Register(new Registration<UserManager>());
            //factory.Register(new Registration<UserStore>());
            //factory.Register(new Registration<Context>(resolver => new Context(connString)));
        }
    }

    public class UserService : AspNetIdentityUserService<User, long>
    {
        private UserManager _userMgr;
        public UserService(UserManager userMgr)
            : base(userMgr)
        {
            _userMgr = userMgr;
        }

        public override async Task<IEnumerable<Claim>> GetProfileDataAsync(ClaimsPrincipal subject, IEnumerable<string> requestedClaimTypes = null)
        {
            if (subject == null) throw new ArgumentNullException("subject");

            long key = ConvertSubjectToKey(subject.GetSubjectId());
            var acct = await userManager.FindByIdAsync(key);
            if (acct == null)
            {
                throw new ArgumentException("Invalid subject identifier");
            }

            return subject.Claims;
        }

        public override async Task<AuthenticateResult> AuthenticateLocalAsync(string username, string password, SignInMessage message = null)
        {
            if (!userManager.SupportsUserPassword)
            {
                return null;
            }

            var user = await FindUserAsync(username);
            if (user == null)
            {
                return null;
            }

            if (userManager.SupportsUserLockout &&
                await userManager.IsLockedOutAsync(user.Id))
            {
                return null;
            }

            var loginresult = await _userMgr.LoginAsync(username, password, message == null ? null : message.ClientId);
            if (loginresult.Result == AbpLoginResultType.Success)
            {
                if (userManager.SupportsUserLockout)
                {
                    userManager.ResetAccessFailedCount(user.Id);
                }

                var result = await PostAuthenticateLocalAsync(user, message);
                if (result != null) return result;

                var claims = await GetClaimsForAuthenticateResult(user);

                return new AuthenticateResult(user.Id.ToString(), await GetDisplayNameForAccountAsync(user.Id), claims.Concat(loginresult.Identity.Claims));
            }
            else if (userManager.SupportsUserLockout)
            {
                await userManager.AccessFailedAsync(user.Id);
            }

            return null;
        }
    }
}
