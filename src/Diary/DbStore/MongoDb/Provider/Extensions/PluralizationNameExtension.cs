using System.Globalization;
using PluralizationService;
using PluralizationService.English;

namespace Diary.DbStore.MongoDb.Extensions
{
    /// <summary>
    /// Extension class for returning plural names
    /// </summary>
    internal static class PluralizationNameExtension
    {
        private static readonly IPluralizationApi Api = InitializeApi();
        private static readonly CultureInfo CultureInfo = new CultureInfo("en-US");

        /// <summary>
        /// Setup class for returning plural names
        /// </summary>
        static IPluralizationApi InitializeApi()
        {
            var builder = new PluralizationApiBuilder();
            builder.AddEnglishProvider();
            return builder.Build();
        }

        /// <summary>
        /// Get plural for name
        /// </summary>
        /// <param name="word">Name</param>
        /// <returns>Plural name</returns>
        internal static string GetPluralizationName(this string word)
        {
            return Api.Pluralize(word, CultureInfo);
        }
    }
}
