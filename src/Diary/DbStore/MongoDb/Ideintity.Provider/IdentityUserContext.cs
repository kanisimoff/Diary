using MongoDB.Driver;

namespace Diary.DbStore.MongoDb.Identity
{
    /// <summary>
    /// Base class for the Entity Framework database context used for identity.
    /// </summary>
    /// <typeparam name="TUser">The type of user objects.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for users and roles.</typeparam>
    public class IdentityUserContext<TUser> : IdentityUserContext<TUser, IdentityUserClaim, IdentityUserLogin, IdentityUserToken>
        where TUser : IdentityUser
    {
        /// <summary>
        /// Initializes a new instance of the db context.
        /// </summary>
        /// <param name="connectionString">The options to be used by a <see cref="MongoDbContext"/>.</param>
        public IdentityUserContext(string connectionString) : base(connectionString) { }
    }

    /// <summary>
    /// Base class for the Entity Framework database context used for identity.
    /// </summary>
    /// <typeparam name="TUser">The type of user objects.</typeparam>
    /// <typeparam name="TUserClaim">The type of the user claim object.</typeparam>
    /// <typeparam name="TUserLogin">The type of the user login object.</typeparam>
    /// <typeparam name="TUserToken">The type of the user token object.</typeparam>
    public abstract class IdentityUserContext<TUser, TUserClaim, TUserLogin, TUserToken> : MongoDbContext
        where TUser : IdentityUser
        where TUserClaim : IdentityUserClaim
        where TUserLogin : IdentityUserLogin
        where TUserToken : IdentityUserToken
    {
        /// <summary>
        /// Initializes a new instance of the class.
        /// </summary>
        /// <param name="connectionString">The options to be used by a <see cref="MongoDbContext"/>.</param>
        public IdentityUserContext(string connectionString) : base(connectionString) { }

        /// <summary>
        /// Gets or sets the <see cref="IMongoCollection{TEntity}"/> of Users.
        /// </summary>
        public IMongoCollection<TUser> Users { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IMongoCollection{TEntity}"/> of User claims.
        /// </summary>
        public IMongoCollection<TUserClaim> UserClaims { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IMongoCollection{TEntity}"/> of User logins.
        /// </summary>
        public IMongoCollection<TUserLogin> UserLogins { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IMongoCollection{TEntity}"/> of User tokens.
        /// </summary>
        public IMongoCollection<TUserToken> UserTokens { get; set; }
    }
}
