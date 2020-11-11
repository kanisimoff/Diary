using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Diary.DbStore.MongoDb.Extensions;
using Diary.DbStore.MongoDb.Interfaces;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Diary.DbStore.MongoDb
{
    /// <summary>
    /// Class for combination of the Unit Of Work and Repository patterns such that 
    /// it can be used to query from a Mongo database and group together changes that 
    /// will then be written back to the store as a unit.
    /// </summary>
    public class MongoDbContext : IMongoDbContext
    {
        #region Fields
        private static object _initializerLock = new object();
        private static bool _isInitialized;
        private static Dictionary<Type, object> _repostoriesMongoDb;
        #endregion

        #region Properties
        /// <summary>
        /// Settings for MongoDb client
        /// </summary>
        public MongoClientSettings Settings { get; }

        /// <summary>
        /// Represent database in MongoDb
        /// </summary>
        public IMongoDatabase DbContext { get; }
        #endregion

        /// <summary>
        /// ctor <see cref="MongoDbContext"/>
        /// </summary>
        /// <param name="connectionString">Connection string to the database</param>
        public MongoDbContext(string connectionString)
        {
            if (string.IsNullOrWhiteSpace(connectionString))
                throw new ArgumentException("Connection string can't be null or empty.");

            try
            {
                var mongoUrl = new MongoUrl(connectionString);
                Settings = MongoClientSettings.FromUrl(mongoUrl);

                if (string.IsNullOrWhiteSpace(mongoUrl.DatabaseName))
                    throw new ArgumentException("Database name can't be null or empty.");

                if (Settings.UseTls)
                {
                    Settings.SslSettings = new SslSettings { EnabledSslProtocols = SslProtocols.Tls12 };
                }

                DbContext = new MongoClient(Settings).GetDatabase(mongoUrl.DatabaseName);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        /// <inheritdoc cref="IMongoDbContext"/>
        public async Task<IMongoCollection<TEntity>> Set<TEntity>() where TEntity : class, IEntity
        {
            LazyInitializer.EnsureInitialized(ref _repostoriesMongoDb, ref _isInitialized, ref _initializerLock);

            var entityType = typeof(TEntity);
            if (false == await IsCollectionExistsAsync<TEntity>().ConfigureAwait(false))
            {
                await DbContext.CreateCollectionAsync(entityType.MongoCollectionName()).ConfigureAwait(false);
            }

            if (!_repostoriesMongoDb.ContainsKey(entityType))
            {
                _repostoriesMongoDb[entityType] = DbContext.GetCollection<TEntity>(entityType.MongoCollectionName());
            }

            return _repostoriesMongoDb[entityType] as IMongoCollection<TEntity>;
        }

        /// <summary>
        /// Сhecks the presence of documents <see cref="TEntity"/> collection  in the database
        /// </summary>
        /// <typeparam name="TEntity">Document type stored in collection</typeparam>
        /// <returns>The result of the presence of a collection in the database</returns>
        private async Task<bool> IsCollectionExistsAsync<TEntity>() where TEntity : IEntity
        {
            var filter = new BsonDocument("name", typeof(TEntity).MongoCollectionName());
            
            //filter by collection name
            var collections = await DbContext.ListCollectionsAsync(new ListCollectionsOptions { Filter = filter }).ConfigureAwait(false);
            
            //check for existence
            return await collections.AnyAsync().ConfigureAwait(false);
        }
    }
}
