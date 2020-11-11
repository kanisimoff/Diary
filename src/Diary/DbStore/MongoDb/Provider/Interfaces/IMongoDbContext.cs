using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using MongoDB.Driver;

namespace Diary.DbStore.MongoDb.Interfaces
{
    /// <summary>
    /// Interface for combination of the Unit Of Work and Repository patterns such that 
    /// it can be used to query from a Mongo database and group together changes that 
    /// will then be written back to the store as a unit.
    /// </summary>
    public interface IMongoDbContext
    {
        /// <summary>
        /// Mongodb client settings
        /// </summary>
        MongoClientSettings Settings { get; }

        /// <summary>
        /// Database Context
        /// </summary>
        IMongoDatabase DbContext { get; }

        /// <summary>
        /// Gets the specified repository for the <typeparamref name="TEntity"/>.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity.</typeparam>
        /// <returns>An instance of type inherited from <see cref="IMongoCollection{TEntity}"/> interface.</returns>
        Task<IMongoCollection<TEntity>> Set<TEntity>() where TEntity : class, IEntity;
    }
}
