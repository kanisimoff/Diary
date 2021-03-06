﻿using Diary.DbStore.MongoDb.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Diary.DbStore.MongoDb
{
    /// <summary>
    /// MongoDb specific extension methods for <see cref="IServiceCollection" />.
    /// </summary>
    public static class MongoDbRegisterService
    {
        /// <summary>
        ///  Adds the services required by the MongoDb database provider for Entity Framework
        ///  to an <see cref="IServiceCollection" />. You use this method when using dependency injection
        ///  in your application, such as with ASP.NET.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <param name="connectionString">Connection string for MongoDb database</param>
        /// <returns>The same service collection so that multiple calls can be chained.</returns>
        public static IServiceCollection AddMongoDb(this IServiceCollection services, string connectionString)
        {
            services.AddSingleton<IMongoDbContext, MongoDbContext>(serviceProvider => new MongoDbContext(connectionString));
            /*
            services.TryAddSingleton(typeof(IMongoDbRepository<>), typeof(MongoDbRepository<>));
            services.TryAddSingleton(typeof(IRepository<>), typeof(MongoDbRepository<>));*/
            return services;
        }
    }
}
