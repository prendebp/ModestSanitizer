using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace ModestSanitizer
{
    public class DateRegex
    {
        public bool CompileRegex { get; set; }
        public DateRegex(bool compileRegex) 
        {
            CompileRegex = compileRegex;
        }
        public void PerformRegexForDateInUSFormat(string dateToClean)
        {
            //Date in US format with support for leap years. SOURCE: https://owasp.org/www-community/OWASP_Validation_Regex_Repository
            string dateRegex = @"^(?:(?:(?:0?[13578]|1[02])(\/|-|\.)31)\1|(?:(?:0?[1,3-9]|1[0-2])(\/|-|\.)(?:29|30)\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:0?2(\/|-|\.)29\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:(?:0?[1-9])|(?:1[0-2]))(\/|-|\.)(?:0?[1-9]|1\d|2[0-8])\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$";

            bool matchOnWindows = false;
            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Fails to match Date Regex in US format mm/dd/yyyy with support for leap years.");
            }
        }

        public void PerformRegexForDateInEuroFormat(string dateToClean)
        {
            //Date in Euro format. SOURCE: http://regexlib.com/DisplayPatterns.aspx?cattabindex=4&categoryId=5
            //See also explanation here: https://stackoverflow.com/questions/8647893/regular-expression-leap-years-and-more/31408642#31408642
            string dateRegex = @"^(?=\d)(?!(?:(?:0?[5-9]|1[0-4])(?:\.|-|\/)10(?:\.|-|\/)(?:1582))|(?:(?:0?[3-9]|1[0-3])(?:\.|-|\/)0?9(?:\.|-|\/)(?:1752)))(31(?!(?:\.|-|\/)(?:0?[2469]|11))|30(?!(?:\.|-|\/)0?2)|(?:29(?:(?!(?:\.|-|\/)0?2(?:\.|-|\/))|(?=\D0?2\D(?:(?!000[04]|(?:(?:1[^0-6]|[2468][^048]|[3579][^26])00))(?:(?:(?:\d\d)(?:[02468][048]|[13579][26])(?!\x20BC))|(?:00(?:42|3[0369]|2[147]|1[258]|09)\x20BC))))))|2[0-8]|1\d|0?[1-9])([-.\/])(1[012]|(?:0?[1-9]))\2((?=(?:00(?:4[0-5]|[0-3]?\d)\x20BC)|(?:\d{4}(?:$|(?=\x20\d)\x20)))\d{4})$";

            bool matchOnWindows = false;
            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Fails to match Date Regex in Euro format dd/mm/yyyy.");
            }
        }

        public void PerformRegexForDateInChineseFormat(string dateToClean)
        {
            //Date in Chinese format. SOURCE: http://regexlib.com/DisplayPatterns.aspx?cattabindex=4&categoryId=5
            //See also explanation here: https://stackoverflow.com/questions/8647893/regular-expression-leap-years-and-more/31408642#31408642
            string dateRegex = @"^(?:(?:(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))(\/|-|\.)(?:0?2\1(?:29)))|(?:(?:(?:1[6-9]|[2-9]\d)?\d{2})(\/|-|\.)(?:(?:(?:0?[13578]|1[02])\2(?:31))|(?:(?:0?[1,3-9]|1[0-2])\2(29|30))|(?:(?:0?[1-9])|(?:1[0-2]))\2(?:0?[1-9]|1\d|2[0-8]))))$";

            bool matchOnWindows = false;

            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Fails to match Date Regex in China format yyyy/mm/dd.");
            }
        }

        public void PerformRegexForDateTimeInUSFormat(string dateToClean)
        {
            //Date in US format with single space hh:mm
            string dateRegex = @"^([0-1]?)([0-9])(\/|-|\.)([0-3]?)([0-9])(\/|-|\.)([0-2])([0-9])([0-9])([0-9]) ([0-2][0-9]\:[0-6][0-9])$";

            bool matchOnWindows = false;
            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Fails to match Date Regex in US format with single space hh:mm.");
            }
        }

        public void PerformRegexForDateTimeWithSecondsInUSFormat(string dateToClean, bool expectTrailingAMorPM)
        {
            string dateRegex;

            if (expectTrailingAMorPM == false)
            {
                dateRegex = @"^([0-1]?)([0-9])(\/|-|\.)([0-3]?)([0-9])(\/|-|\.)([0-2])([0-9])([0-9])([0-9]) ([0-2]?[0-9]\:[0-6][0-9]\:[0-6][0-9])$";
            }
            else //expect AM or PM
            {
                dateRegex = @"^([0-1]?)([0-9])(\/|-|\.)([0-3]?)([0-9])(\/|-|\.)([0-2])([0-9])([0-9])([0-9]) ([0-2]?[0-9]\:[0-6][0-9]\:[0-6][0-9]) ([A|P]M)$";
            }

            bool matchOnWindows = false;

            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Fails to match Date Regex in US format with single space hh:mm:ss and with optional AM or PM");
            }
        }

        public void PerformRegexForDateTimeWithSecondsAsUTCWithDelimiters(string dateToClean)
        {
            //Date in UTC format where string must contain only date-time and no other chars. 
            //SOURCE: https://stackoverflow.com/questions/25568134/regex-to-verify-utc-date-time-format
            string dateRegex = @"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z?$";
        
            bool matchOnWindows = false;

            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Invalid date: format fails to match UTC with delimiters.");
            }
        }

        public void PerformRegexForDateTimeWithSecondsAsUTCWithDelimitersAndZone(string dateToClean)
        {
            //Date in UTC format where string must contain only date-time and no other chars. 
            //SOURCE: https://stackoverflow.com/questions/25568134/regex-to-verify-utc-date-time-format
            string dateRegex = @"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\-|\+)([0-9]{2}:[0-9]{2})Z?$";

            bool matchOnWindows = false;

            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Invalid date: format fails to match UTC with delimiters and zone.");
            }
        }

        public void PerformRegexForDateTimeWithSecondsAsUTCWithoutDelimiters(string dateToClean)
        {
            //Date in UTC format where string must contain only date-time and no other chars. 
            //SOURCE: https://stackoverflow.com/questions/25568134/regex-to-verify-utc-date-time-format
            string dateRegex = @"^[0-9]{4}[0-9]{2}[0-9]{2}T[0-9]{2}[0-9]{2}[0-9]{2}$"; //no trailing Z

            bool matchOnWindows = false;

            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Invalid date: format fails to match UTC without delimiters.");
            }
        }
        public void PerformRegexForDateTimeWithMillisecondsInUSFormat(string dateToClean, bool expectTrailingAMorPM)
        {
            string dateRegex;

            if (expectTrailingAMorPM == false)
            {
                dateRegex = @"^([0-1]?)([0-9])(\/|-|\.)([0-3]?)([0-9])(\/|-|\.)([0-2])([0-9]{3}) ([0-2]?[0-9]\:[0-6][0-9]\:[0-6][0-9]\.[0-9]{3})$";
            }
            else //expect AM or PM
            {
                dateRegex = @"^([0-1]?)([0-9])(\/|-|\.)([0-3]?)([0-9])(\/|-|\.)([0-2])([0-9]{3}) ([0-2]?[0-9]\:[0-6][0-9]\:[0-6][0-9]\.[0-9]{3}) ([A|P]M)$";
            }

            bool matchOnWindows = false;

            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Fails to match Date Regex in US format with single space H:m:ss.fff and with optional AM or PM.");
            }
        }

        public void PerformRegexForDateTimeInSQLServerFormat(string dateToClean)
        {
            //SOURCE https://stackoverflow.com/questions/8647893/regular-expression-leap-years-and-more/31408642#31408642
            string dateRegex = @"^(?:(?:(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))(\/|-|\.)(?:0?2\1(?:29)))|(?:(?:(?:1[6-9]|[2-9]\d)?\d{2})(\/|-|\.)(?:(?:(?:0?[13578]|1[02])\2(?:31))|(?:(?:0?[1,3-9]|1[0-2])\2(29|30))|(?:(?:0?[1-9])|(?:1[0-2]))\2(?:0?[1-9]|1\d|2[0-8])))) ([0-2]?[0-9]\:[0-6][0-9]\:[0-6][0-9]\.[0-9]{3})$";
           
            bool matchOnWindows = false;
            if (CompileRegex)
            {
                //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
            else
            {
                matchOnWindows = Regex.IsMatch(dateToClean, dateRegex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            if (!matchOnWindows)
            {
                throw new Exception("Fails to match Date Regex in SQL Server format.");
            }
        }
    }//end of class
}//end of namespace
