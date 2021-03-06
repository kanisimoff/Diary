﻿using System.Globalization;
using System.Reflection;
using System.Resources;

namespace Diary.DbStore.MongoDb.Identity
{
    internal static class Resources
    {
        private static readonly ResourceManager _resourceManager
            = new ResourceManager("ItMastersPro.NoSql.Repository.MongoDb.Identity.Resources", typeof(Resources).GetTypeInfo().Assembly);

        /// <summary>
        /// [ProtectedPersonalData] only works strings by default.
        /// </summary>
        internal static string CanOnlyProtectStrings
        {
            get => GetString("CanOnlyProtectStrings");
        }

        /// <summary>
        /// [ProtectedPersonalData] only works strings by default.
        /// </summary>
        internal static string FormatCanOnlyProtectStrings()
            => GetString("CanOnlyProtectStrings");

        /// <summary>
        /// AddEntityFrameworkStores can only be called with a role that derives from IdentityRole&lt;TKey&gt;.
        /// </summary>
        internal static string NotIdentityRole
        {
            get => GetString("NotIdentityRole");
        }

        /// <summary>
        /// AddEntityFrameworkStores can only be called with a role that derives from IdentityRole&lt;TKey&gt;.
        /// </summary>
        internal static string FormatNotIdentityRole()
            => GetString("NotIdentityRole");

        /// <summary>
        /// AddEntityFrameworkStores can only be called with a user that derives from IdentityUser&lt;TKey&gt;.
        /// </summary>
        internal static string NotIdentityUser
        {
            get => GetString("NotIdentityUser");
        }

        /// <summary>
        /// AddEntityFrameworkStores can only be called with a user that derives from IdentityUser&lt;TKey&gt;.
        /// </summary>
        internal static string FormatNotIdentityUser()
            => GetString("NotIdentityUser");

        /// <summary>
        /// Role {0} does not exist.
        /// </summary>
        internal static string RoleNotFound
        {
            get => GetString("RoleNotFound");
        }

        /// <summary>
        /// Role {0} does not exist.
        /// </summary>
        internal static string FormatRoleNotFound(object p0)
            => string.Format(CultureInfo.CurrentCulture, GetString("RoleNotFound"), p0);

        /// <summary>
        /// Value cannot be null or empty.
        /// </summary>
        internal static string ValueCannotBeNullOrEmpty
        {
            get => GetString("ValueCannotBeNullOrEmpty");
        }

        /// <summary>
        /// Value cannot be null or empty.
        /// </summary>
        internal static string FormatValueCannotBeNullOrEmpty()
            => GetString("ValueCannotBeNullOrEmpty");

        private static string GetString(string name, params string[] formatterNames)
        {
            var value = _resourceManager.GetString(name);

            System.Diagnostics.Debug.Assert(value != null);

            if (formatterNames != null)
            {
                for (var i = 0; i < formatterNames.Length; i++)
                {
                    value = value.Replace("{" + formatterNames[i] + "}", "{" + i + "}");
                }
            }

            return value;
        }
    }
}
