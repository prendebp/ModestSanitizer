using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ModestSanitizer
{
    public static class Utility
    {
        public enum DateDelimiter
        {
            ForwardSlash = 1,
            Dash = 2,
            Dot = 3,
            UTCWithDelimiters = 4,
            UTCWithoutDelimiters = 5,
        }

        public enum DateDataType
        {
            Date = 1,
            DateTime = 2,
            DateTimeWithSeconds = 3,
            DateTimeWithMilliseconds = 4,
            SQLServerDateTime = 5
        }
        public static string GetDateTimeNowFormattedForSQLServer()
        {
            //SOURCE: https://stackoverflow.com/questions/17418258/datetime-format-to-sql-format-using-c-sharp
            DateTime myDateTime = DateTime.Now;
            string sqlFormattedDate = myDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff");

            return sqlFormattedDate;
        }

        public static string GetDateTimeTodayFormattedAsShortDate() //Date = 1 && ForwardSlash = 1
        {
            DateTime myDateTime = DateTime.Today;
            return myDateTime.ToString("s"); //Example 6/4/2020
        }
        public static string GetDateTimeNowFormattedAsSortableDateTime() //DateTime = 2 && UTCWithDelimiters
        {
            DateTime myDateTime = DateTime.Now;
            return myDateTime.ToString("yyyy-MM-ddTHH:mm:ss"); //Example 2015-12-08T15:15:19
        }
        public static string GetDateTimeNowFormattedAsUTCString() //DateTime = 2 && UTCWithDelimiters with space instead of 'T'
        {
            DateTime myDateTime = DateTime.Now;
            return myDateTime.ToString("u"); //Example 2015-12-08 15:15:19Z
        }

        public static string GetDateTimeNowFormattedAsGeneralDateTime() //DateTime = 2 && ForwardSlash = 1
        {
            DateTime myDateTime = DateTime.Now;
            return myDateTime.ToString("g"); //Example 12/8/2015 15:15 
        }

        public static string GetDateTimeNowFormattedAsGeneralDateTimeWithMillisecondsAndAMPM() //DateTimeWithMilliseconds = 2 && ForwardSlash = 1
        {
            DateTime myDateTime = DateTime.Now;
            return myDateTime.ToString("MM/dd/yyyy hh:mm:ss.fff tt"); //Example 07/16/2008 08:32:45.126 AM
        }

        public static string GetDateTimeNowFormattedAsGeneralDateTimeWithMilliseconds() //DateTimeWithMilliseconds = 2 && ForwardSlash = 1
        {
            DateTime myDateTime = DateTime.Now;
            return myDateTime.ToString("MM/dd/yyyy hh:mm:ss.fff"); //Example 07/16/2008 08:32:45.126
        }

        public static string GetDateTimeNowFormattedAsGeneralDateTimeWithSeconds() //DateTimeWithMilliseconds = 2 && ForwardSlash = 1
        {
            DateTime myDateTime = DateTime.Now;
            return myDateTime.ToString("MM/dd/yyyy hh:mm:ss"); //Example 07/16/2008 08:32:45
        }

        public static string GetDateTimeNowFormattedAsUTCStringWithTimeZone()
        {
            DateTime myDateTime = DateTime.Now;
            return myDateTime.ToString("yyyy-MM-ddTHH:mm:ssK");
        }
        //SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
        //format.setTimeZone(TimeZone.getTimeZone("UTC"));
        //EXAMPLE 2015 - 12 - 01T00: 00:00.000
        //yyyy - MM - dd'T'HH: mm: ss.SSSZZ or yyyyMMdd'T'HHmmss.SSSZ
        //Central Daylight Time| subtract 5 hours from UTC
        //Central Standard Time| subtract 6 hours from UTC

    }//class
}//namespace
