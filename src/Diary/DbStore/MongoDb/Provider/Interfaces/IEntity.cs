using MongoDB.Bson;

namespace Diary.DbStore.MongoDb.Interfaces
{
    /// <summary>
    /// This entity class represents a document that can be stored in MongoDb.
    /// Your document must implement this class in order for the MongoDbRepository to handle them.
    /// </summary>
    public interface IEntity
    {
        /// <summary>
        /// MongoDB identity key
        /// </summary>
        ObjectId Id { get; set; }
    }
}
