﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizer
{
    /// <summary>
    ///  MinMax = 1
    ///  ReduceToValidValue (e.g. max value of a number)
    //   Why? To protect against buffer overflow attacks, e.g. if using unsafe keyword: https://stackoverflow.com/questions/9343665/are-buffer-overflow-exploits-possible-in-c
    /// </summary>
    public class MinMax
    {
        public bool CompileRegex { get; set; }
        public Truncate Truncate { get; set; }
        public NormalizeOrLimit NormalizeOrLimit { get; set; }
        public SaniApproach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public MinMax()
        {
        }

        public MinMax(SaniApproach sanitizerApproach)
        {
            SanitizerApproach = sanitizerApproach;
        }

        public MinMax(Truncate truncate, NormalizeOrLimit normalizeOrLimit, SaniApproach sanitizerApproach, bool compileRegex, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            Truncate = truncate;
            NormalizeOrLimit = normalizeOrLimit;
            CompileRegex = compileRegex;
            SaniExceptions = saniExceptions;
        }

        /// <summary>
        /// ReduceToValidMaxMinValues - enforce max and min value of a nullable long (SQL Server BigInt)
        /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
        /// </summary>
        /// <param name="longToClean"></param>
        /// <returns></returns>         
        public long? ReduceToValidValue(string longToClean, long longMaxValue, long longMinValue)
        {
            long? tmpResult = 0;

            try
            {
                if (String.IsNullOrWhiteSpace(longToClean))
                {
                    tmpResult = null;
                }
                else
                {
                    long value;

                    if (Math.Min(longMaxValue, longMinValue) == longMaxValue)
                    {
                        throw new Exception("Invalid parameters: minimum value cannot be greater than the maximum value.");
                    }

                    bool isSuccess = long.TryParse(longToClean, out value);
                    if (isSuccess)
                    {
                        if (Math.Min(value, longMinValue) == value)
                        {
                            tmpResult = longMinValue;//if min value has to be applied then apply it.
                        }
                        else //otherwise check whether the max value needs to be applied.
                        {
                            if (Math.Max(value, longMaxValue) == value)
                            {
                                tmpResult = longMaxValue;
                            }
                            else
                            {
                                tmpResult = value;
                            }
                        }
                    }
                    else
                    {
                        throw new Exception("Parse Failure.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException(longToClean, ex);
            }
            return tmpResult;
        }

        public enum CurrencySeparators
        {
            xCommaxDotx = 1, // default en-US
            xDotxCommax = 2,
            xSpacexDotx = 3,
            xSpacexCommax = 4      
        }
        
        /// <summary>
        /// ReduceToValidMaxMinValues - enforce max and min value of a nullable decimal
        /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
        /// </summary>
        /// <param name="decimalToClean"></param>
        /// <returns></returns>         
        public decimal? ReduceToValidValue(string decimalToClean, decimal decimalMaxValue, decimal decimalMinValue, bool allowNegativeSign, CurrencySeparators currencySeparators = CurrencySeparators.xCommaxDotx)
        {
            decimal? tmpResult = 0;

            try
            {
                if (String.IsNullOrWhiteSpace(decimalToClean))
                {
                    tmpResult = null;
                }
                else
                {
                    decimal value;

                    if (Math.Min(decimalMaxValue, decimalMinValue) == decimalMaxValue)
                    {
                        throw new Exception("Invalid parameters: minimum value cannot be greater than the maximum value.");
                    }

                    if (!allowNegativeSign)
                    {
                        if (decimalToClean.IndexOf("-") > -1)
                        {
                            throw new Exception("Negative Sign is NOT allowed.");
                        }
                    }

                    StringComparison ic = StringComparison.OrdinalIgnoreCase;

                    //decimalToClean = RemoveAnyExpectedCurrencySymbols(decimalToClean, currencyType, ic);

                    //Remove these rare occurences
                    decimalToClean = Replace(decimalToClean, "%", String.Empty, ic); //Percent 
                    decimalToClean = Replace(decimalToClean, "NaN", String.Empty, ic); //NaNSymbol 
                    decimalToClean = Replace(decimalToClean, "‰", String.Empty, ic); //PerMilleSymbol 
                    decimalToClean = Replace(decimalToClean, "Infinity", String.Empty, ic); //PositiveInfinitySymbol
                    decimalToClean = Replace(decimalToClean, "+", String.Empty, ic); //PositiveSign
                    decimalToClean = Replace(decimalToClean, "-Infinity", String.Empty, ic); //NegativeInfinitySymbol

                    decimalToClean = NormalizeOrLimit.LimitToASCIINumbersOnly(decimalToClean, true, true, allowNegativeSign, true);

                    NumberStyles styles = NumberStyles.Currency;
                    CultureInfo culture = null;

                    if (currencySeparators == CurrencySeparators.xCommaxDotx)
                    {
                        culture = CultureInfo.CreateSpecificCulture("en-US");

                        culture.NumberFormat.CurrencyGroupSeparator = ",";
                        culture.NumberFormat.NumberGroupSeparator = ",";
                        culture.NumberFormat.PercentGroupSeparator = ",";

                        culture.NumberFormat.CurrencyDecimalSeparator = ".";
                        culture.NumberFormat.NumberDecimalSeparator = ".";
                        culture.NumberFormat.PercentDecimalSeparator = ".";
                    }

                    if (currencySeparators == CurrencySeparators.xDotxCommax)
                    {
                        culture = CultureInfo.CreateSpecificCulture("es-ES");//Spain

                        culture.NumberFormat.CurrencyGroupSeparator = ".";
                        culture.NumberFormat.NumberGroupSeparator = ".";
                        culture.NumberFormat.PercentGroupSeparator = ".";

                        culture.NumberFormat.CurrencyDecimalSeparator = ",";
                        culture.NumberFormat.NumberDecimalSeparator = ",";
                        culture.NumberFormat.PercentDecimalSeparator = ",";
                    }

                    if (currencySeparators == CurrencySeparators.xSpacexDotx)
                    {
                        culture = CultureInfo.CreateSpecificCulture("sv-SE");//Sweden

                        culture.NumberFormat.CurrencyGroupSeparator = " ";
                        culture.NumberFormat.NumberGroupSeparator = " ";
                        culture.NumberFormat.PercentGroupSeparator = " ";

                        culture.NumberFormat.CurrencyDecimalSeparator = ".";
                        culture.NumberFormat.NumberDecimalSeparator = ".";
                        culture.NumberFormat.PercentDecimalSeparator = ".";
                    }

                    if (currencySeparators == CurrencySeparators.xSpacexCommax)
                    {
                        culture = CultureInfo.CreateSpecificCulture("fr-FR");//France

                        culture.NumberFormat.CurrencyGroupSeparator = " ";
                        culture.NumberFormat.NumberGroupSeparator = " ";
                        culture.NumberFormat.PercentGroupSeparator = " ";

                        culture.NumberFormat.CurrencyDecimalSeparator = ",";
                        culture.NumberFormat.NumberDecimalSeparator = ",";
                        culture.NumberFormat.PercentDecimalSeparator = ",";
                    }

                    culture.NumberFormat.NegativeSign = "-";
                    styles = (allowNegativeSign) ? (styles | NumberStyles.AllowLeadingSign) : styles;

                    bool isSuccess = decimal.TryParse(decimalToClean, styles, culture, out value);
                    if (isSuccess)
                    {
                        if (Math.Min(value, decimalMinValue) == value)
                        {
                            tmpResult = decimalMinValue;//if min value has to be applied then apply it.
                        }
                        else //otherwise check whether the max value needs to be applied.
                        {
                            if (Math.Max(value, decimalMaxValue) == value)
                            {
                                tmpResult = decimalMaxValue;
                            }
                            else
                            {
                                tmpResult = value;
                            }
                        }
                    }
                    else
                    {
                        throw new Exception("Parse Failure.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException(decimalToClean, ex);
            }
            return tmpResult;
        }

        //TODO: Create new CurrencyCleanse? To monitor for whitelisted currencies or else log exceptions
        //public enum CurrencyType
        //{
        //    None = 0,
        //    USDollarSign = 1,
        //    BritishPound = 2,
        //    Euro = 3,
        //    CanadianDollar = 4,
        //    MexicanPeso = 5,
        //    All = 6
        //}
        //private static string RemoveAnyExpectedCurrencySymbols(string decimalToClean, CurrencyType currencyType, StringComparison ic)
        //{
        //    //Remove any expected currency symbols to assure successful parsing to Decimal type
        //    if (currencyType == CurrencyType.USDollarSign)
        //    {
        //        decimalToClean = Replace(decimalToClean, "USD", String.Empty, ic); //ISO 4217 currency name
        //        decimalToClean = decimalToClean.Replace("$", String.Empty);//US Dollar
        //    }
        //    if (currencyType == CurrencyType.Euro)
        //    {
        //        decimalToClean = Replace(decimalToClean, "EUR", String.Empty, ic); //ISO 4217 currency name
        //        decimalToClean = decimalToClean.Replace("€", String.Empty); //Euro is U+20AC                        
        //    }
        //    if (currencyType == CurrencyType.BritishPound)
        //    {
        //        decimalToClean = Replace(decimalToClean, "GBP", String.Empty, ic); //ISO 4217 currency name
        //        decimalToClean = decimalToClean.Replace("￡", String.Empty); //British Pound U+FFE1                        
        //    }
        //    if (currencyType == CurrencyType.CanadianDollar)
        //    {
        //        decimalToClean = Replace(decimalToClean, "CAD", String.Empty, ic); //ISO 4217 currency name
        //        decimalToClean = Replace(decimalToClean, "Can$", String.Empty, ic); //longer string first
        //        decimalToClean = Replace(decimalToClean, "CA$", String.Empty, ic); //subset second
        //        decimalToClean = Replace(decimalToClean, "C$", String.Empty, ic); //subset third
        //        decimalToClean = decimalToClean.Replace("$", String.Empty);//CAN Dollar

        //    }
        //    if (currencyType == CurrencyType.MexicanPeso)
        //    {
        //        decimalToClean = Replace(decimalToClean, "MXN", String.Empty, ic); //ISO 4217 currency name
        //        decimalToClean = Replace(decimalToClean, "Mex$", String.Empty, ic); //longer string first
        //        decimalToClean = decimalToClean.Replace("$", String.Empty);//MEX Peso                     
        //    }
        //    if (currencyType == CurrencyType.All)
        //    {
        //decimalToClean = Replace(decimalToClean, "USD", String.Empty, ic); //ISO 4217 currency name
        //decimalToClean = Replace(decimalToClean, "EUR", String.Empty, ic); //ISO 4217 currency name                        
        //decimalToClean = Replace(decimalToClean, "GBP", String.Empty, ic); //ISO 4217 currency name                           
        //decimalToClean = Replace(decimalToClean, "CAD", String.Empty, ic); //ISO 4217 currency name
        //decimalToClean = Replace(decimalToClean, "Can$", String.Empty, ic); //longer string first
        //decimalToClean = Replace(decimalToClean, "CA$", String.Empty, ic); //subset second
        //decimalToClean = Replace(decimalToClean, "C$", String.Empty, ic); //subset third
        //decimalToClean = Replace(decimalToClean, "MXN", String.Empty, ic); //ISO 4217 currency name
        //decimalToClean = Replace(decimalToClean, "Mex$", String.Empty, ic); //longer string first
        //decimalToClean = decimalToClean.Replace("€", String.Empty); //Euro is U+20AC 
        //decimalToClean = decimalToClean.Replace("￡", String.Empty); //British Pound U+FFE1
        //decimalToClean = decimalToClean.Replace("$", String.Empty); //US Dollar, CAN Dollar, MEX Peso 
        //    }

        //    return decimalToClean;
        //}

        //SOURCE: https://stackoverflow.com/questions/6275980/string-replace-ignoring-case
        private static string Replace(string str, string old, string @new, StringComparison comparison)
        {
            @new = @new ?? "";
            if (string.IsNullOrEmpty(str) || string.IsNullOrEmpty(old) || old.Equals(@new, comparison))
                return str;
            int foundAt = 0;
            while ((foundAt = str.IndexOf(old, foundAt, comparison)) != -1)
            {
                str = str.Remove(foundAt, old.Length).Insert(foundAt, @new);
                foundAt += @new.Length;
            }
            return str;
        }

        /// <summary>
        /// ReduceToValidMaxMinValues - enforce max and min value of a nullable integer
        /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
        /// </summary>
        /// <param name="intToClean"></param>
        /// <returns></returns>   
        public int? ReduceToValidValue(string intToClean, int intMaxValue, int intMinValue)
        {
            int? tmpResult = 0;

            try
            {
                if (String.IsNullOrWhiteSpace(intToClean))
                {
                    tmpResult = null;
                }
                else
                {
                    int value;
                    if (Math.Min(intMaxValue, intMinValue) == intMaxValue)
                    {
                        throw new Exception("Invalid parameters: minimum value cannot be greater than the maximum value.");
                    }

                    bool isSuccess = int.TryParse(intToClean, out value);
                    if (isSuccess)
                    {
                        if (Math.Min(value, intMinValue) == value)
                        {
                                tmpResult = intMinValue;//if min value has to be applied then apply it.
                        }
                        else //otherwise check whether the max value needs to be applied.
                        {
                            if (Math.Max(value, intMaxValue) == value)
                            {
                                tmpResult = intMaxValue;
                            }
                            else
                            {
                                tmpResult = value;
                            }
                        }
                    }
                    else
                    {
                        throw new Exception("Parse Failure.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException(intToClean, ex);
            }
            return tmpResult;
        }

        /// <summary>
        /// ReduceToValidMaxMinValues - enforce max and min value of a nullable boolean
        /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
        /// </summary>
        /// <param name="boolToClean"></param>
        /// <returns></returns>   
        public bool? ReduceToValidValue(string boolToClean)
        {
            bool? tmpResult = false;

            try
            {
                if (String.IsNullOrWhiteSpace(boolToClean))
                {
                    tmpResult = null;
                }
                else
                {
                    bool value;

                    string truncatedValue = Truncate.TruncateToValidLength(boolToClean, 5);
                    bool isSuccess = bool.TryParse(truncatedValue, out value);

                    if (isSuccess)
                    {
                        tmpResult = value;
                    }
                    else
                    {
                        throw new Exception("Parse Failure.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException(boolToClean, ex);
            }
            return tmpResult;
        }
        
        public enum DateFormat
        {
            US = 1,
            Euro = 2,
            China = 3,
            SQLServer = 4
        }

        /// <summary>
        /// ReduceToValidMaxMinValues - enforce max and min value of a nullable decimal
        /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
        /// </summary>
        /// <param name="decimalToClean"></param>
        /// <returns></returns>         
        public DateTime? ReduceToValidValue(string dateToClean, DateTime dateMaxValue, DateTime dateMinValue, Utility.DateDataType dateDataType, Utility.DateDelimiter dateDelimiter, DateFormat dateFormat, bool expectTrailingAMorPM)
        {
            String[] strFormat = null;
            DateTime? tmpResult = null;

            try
            {
                if (String.IsNullOrWhiteSpace(dateToClean))
                {
                    tmpResult = null;
                }
                else
                {
                    DateTime value;

                    if (DateTime.Compare(dateMinValue.ToUniversalTime(), dateMaxValue.ToUniversalTime()) > 0)
                    {
                        throw new Exception("Invalid parameters: minimum date cannot be greater than the maximum date.");
                    }

                    if (dateDelimiter == Utility.DateDelimiter.ForwardSlash) 
                    {
                        if (dateToClean.IndexOf(@"/") == -1)
                        {
                            throw new Exception("Invalid date: missing forward slash delimiter.");
                        }
                    }
                    if (dateDelimiter == Utility.DateDelimiter.Dash)
                    {
                        if (dateToClean.IndexOf(@"-") == -1)
                        {
                            throw new Exception("Invalid date: missing dash delimiter.");
                        }
                    }

                    if (dateDelimiter == Utility.DateDelimiter.Dot)
                    {
                        if (dateToClean.IndexOf(@".") == -1)
                        {
                            throw new Exception("Invalid date: missing dot delimiter.");
                        }
                    }

                    //This includes Truncate to 33 chars (longest datetime format)
                    dateToClean = NormalizeOrLimit.LimitToASCIIDateTimesOnly(dateToClean, dateDelimiter, dateDataType, expectTrailingAMorPM);

                    #region Regex checks and strFormat assignment

                    DateRegex dateRegexObj = new DateRegex(CompileRegex);

                    //Perform specific Regex checks where possible after having already normalized the unicode string and reduced it to ASCII-like characters.
                    if ((dateDataType == Utility.DateDataType.Date) && (dateFormat == DateFormat.US)) //Delimiter slash, dash, or dot
                    {
                        strFormat = new string[] { "M/d/yyyy", "MM/dd/yyyy" }; //Example 6/14/2020

                        if (dateDelimiter == Utility.DateDelimiter.Dot)
                        {
                            strFormat = new string[] { "M.d.yyyy", "MM.dd.yyyy" };
                        }
                        if (dateDelimiter == Utility.DateDelimiter.Dash)
                        {
                            strFormat = new string[] { "M-d-yyyy", "MM-dd-yyyy" };
                        }
                        dateRegexObj.PerformRegexForDateInUSFormat(dateToClean);
                    }

                    if ((dateDataType == Utility.DateDataType.Date) && (dateFormat == DateFormat.Euro)) //Delimiter slash, dash, or dot
                    {
                        strFormat = new string[] { "d/M/yyyy", "dd/MM/yyyy" }; //Example 28/02/2005

                        if (dateDelimiter == Utility.DateDelimiter.Dot)
                        {
                            strFormat = new string[] { "d.M.yyyy", "dd.MM.yyyy" };
                        }
                        if (dateDelimiter == Utility.DateDelimiter.Dash)
                        {
                            strFormat = new string[] { "d-M-yyyy", "dd-MM-yyyy" };
                        }
                        dateRegexObj.PerformRegexForDateInEuroFormat(dateToClean);
                    }

                    if ((dateDataType == Utility.DateDataType.Date) && (dateFormat == DateFormat.China)) //Delimiter slash, dash, or dot
                    {
                        strFormat = new string[] { "yyyy/M/d", "yyyy/MM/dd" }; //Example 2009/6/15

                        if (dateDelimiter == Utility.DateDelimiter.Dot)
                        {
                            strFormat = new string[] { "yyyy.M.d", "yyyy.MM.dd" };
                        }
                        if (dateDelimiter == Utility.DateDelimiter.Dash)
                        {
                            strFormat = new string[] { "yyyy-M-d", "yyyy-MM-dd" };
                        }
                        dateRegexObj.PerformRegexForDateInChineseFormat(dateToClean);
                    }

                    //Not the best regex here but we still have DateTime.ParseExact further below.
                    if ((dateDataType == Utility.DateDataType.DateTime) && (dateFormat == DateFormat.US)) //Delimiter slash, dash, or dot
                    {
                        strFormat = null; //Example 02/18/1753 15:15  NOTE: capital H indicates 24-hour time.

                        if (dateDelimiter == Utility.DateDelimiter.ForwardSlash)
                        {
                            strFormat = new string[] { "M/d/yyyy H:m", "MM/dd/yyyy H:m" };
                        }
                        if (dateDelimiter == Utility.DateDelimiter.Dot)
                        {
                            strFormat = new string[] { "M.d.yyyy H:m", "MM.dd.yyyy H:m" };
                        }
                        if (dateDelimiter == Utility.DateDelimiter.Dash)
                        {
                            strFormat = new string[] { "M-d-yyyy H:m", "MM-dd-yyyy H:m" };
                        }

                        dateRegexObj.PerformRegexForDateTimeInUSFormat(dateToClean);
                    }

                    //Not the best regex here but we still have DateTime.ParseExact further below.
                    if ((dateDataType == Utility.DateDataType.DateTimeWithSeconds) && (dateFormat == DateFormat.US) && !(dateDelimiter == Utility.DateDelimiter.UTCWithDelimiters || dateDelimiter == Utility.DateDelimiter.UTCWithoutDelimiters)) //Delimiter slash, dash, or dot
                    {
                        strFormat = null;
                        //Example 06/05/2009 15:15:33 or 06/05/2009 03:15:33 PM

                        //Date in US format with single space H:m:ss and with optional AM or PM
                        if (expectTrailingAMorPM == false)
                        {
                            if (dateDelimiter == Utility.DateDelimiter.ForwardSlash) //NOTE: capital H indicates 24-hour time.
                            {
                                strFormat = new string[] { "M/d/yyyy H:m:s", "MM/dd/yyyy H:m:s" };
                            }
                            if (dateDelimiter == Utility.DateDelimiter.Dot)
                            {
                                strFormat = new string[] { "M.d.yyyy H:m:s", "MM.dd.yyyy H:m:s" };
                            }
                            if (dateDelimiter == Utility.DateDelimiter.Dash)
                            {
                                strFormat = new string[] { "M-d-yyyy H:m:s", "MM-dd-yyyy H:m:s" };
                            }
                        }
                        else //expect AM or PM
                        {
                            if (dateDelimiter == Utility.DateDelimiter.ForwardSlash) //NOTE: capital h indicates regular time not military.
                            {
                                strFormat = new string[] { "M/d/yyyy h:m:s tt", "M/d/yyyy hh:mm:ss tt", "MM/dd/yyyy h:m:s tt", "MM/dd/yyyy hh:mm:ss tt" };
                            }
                            if (dateDelimiter == Utility.DateDelimiter.Dot)
                            {
                                strFormat = new string[] { "M.d.yyyy h:m:s tt", "M.d.yyyy hh:mm:ss tt", "MM.dd.yyyy h:m:s tt", "MM.dd.yyyy hh:mm:ss tt" };
                            }
                            if (dateDelimiter == Utility.DateDelimiter.Dash)
                            {
                                strFormat = new string[] { "M-d-yyyy h:m:s tt", "M-d-yyyy hh:mm:ss tt", "MM-dd-yyyy h:m:s tt", "MM-dd-yyyy hh:mm:ss tt" };
                            }
                        }
                        dateRegexObj.PerformRegexForDateTimeWithSecondsInUSFormat(dateToClean, expectTrailingAMorPM);
                    }

                    //Not the best regex here but we still have DateTime.ParseExact further below.
                    if ((dateDataType == Utility.DateDataType.DateTimeWithMilliseconds) && (dateFormat == DateFormat.US)) //Delimiter slash, dash, or dot
                    {
                        strFormat = null; //Example 06/05/2009 15:15:33.001 OR 06/05/2009 03:05:03.003 PM

                        //Date in US format with single space H:m:ss.fff and with optional AM or PM  
                        string dateRegex = null;

                        //NOTE: M = single-digit month is formatted WITHOUT a leading zero. MM = single-digit month is formatted WITH a leading zero.
                        //      H = single-digit hour is formatted WITHOUT a leading zero.  HH = single-digit hour is formatted WITH a leading zero.
                        //      d = single-digit day is formatted WITHOUT a leading zero.   dd = single-digit day is formatted WITH a leading zero.
                        if (expectTrailingAMorPM == false)
                        {
                            if (dateDelimiter == Utility.DateDelimiter.ForwardSlash) //NOTE: capital H indicates 24-hour time. 
                            {
                                strFormat = new string[] { "M/d/yyyy H:m:s.fff", "MM/dd/yyyy H:m:s.fff", "MM/dd/yyyy HH:mm:ss.fff", "M/d/yyyy HH:m:s.fff" };
                            }
                            if (dateDelimiter == Utility.DateDelimiter.Dot)
                            {
                                strFormat = new string[] { "M.d.yyyy H:m:s.fff", "MM.dd.yyyy H:m:s.fff", "MM.dd.yyyy HH:mm:ss.fff", "M.d.yyyy HH:m:s.fff" };
                            }
                            if (dateDelimiter == Utility.DateDelimiter.Dash)
                            {
                                strFormat = new string[] { "M-d-yyyy H:m:s.fff", "MM-dd-yyyy H:m:s.fff", "MM-dd-yyyy HH:mm:ss.fff", "M-d-yyyy HH:m:s.fff" };
                            }
                            dateRegex = @"^([0-1]?)([0-9])(\/|-|\.)([0-3]?)([0-9])(\/|-|\.)([0-2])([0-9]{3}) ([0-2]?[0-9]\:[0-6][0-9]\:[0-6][0-9]\.[0-9]{3})$";
                        }
                        else //expect AM or PM
                        {
                            if (dateDelimiter == Utility.DateDelimiter.ForwardSlash) //NOTE: capital h indicates regular time not military.
                            {
                                strFormat = new string[] { "M/d/yyyy h:m:s.fff tt", "M/d/yyyy hh:mm:ss.fff tt", "MM/dd/yyyy h:m:s.fff tt", "MM/dd/yyyy hh:mm:ss.fff tt" };
                            }
                            if (dateDelimiter == Utility.DateDelimiter.Dot)
                            {
                                strFormat = new string[] { "M.d.yyyy h:m:s.fff tt", "M.d.yyyy hh:mm:ss.fff tt", "MM.dd.yyyy h:m:s.fff tt", "MM.dd.yyyy hh:mm:ss.fff tt" };
                            }
                            if (dateDelimiter == Utility.DateDelimiter.Dash)
                            {
                                strFormat = new string[] { "M-d-yyyy h:m:s.fff tt", "M-d-yyyy hh:mm:ss.fff tt", "MM-dd-yyyy h:m:s.fff tt", "MM-dd-yyyy hh:mm:ss.fff tt" };
                            }
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

                    if ((dateDataType == Utility.DateDataType.SQLServerDateTime) && (dateFormat == DateFormat.SQLServer)) //Delimiter slash, dash, or dot
                    {
                        strFormat = strFormat = new string[] { "yyyy-MM-dd H:m:s.fff", "yyyy-MM-dd HH:mm:ss.fff" }; //Example 2019-01-25 16:01:36.000

                        //Date in SQL Server format
                        string dateRegex = null;

                        //SOURCE https://stackoverflow.com/questions/8647893/regular-expression-leap-years-and-more/31408642#31408642
                        dateRegex = @"^(?:(?:(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))(\/|-|\.)(?:0?2\1(?:29)))|(?:(?:(?:1[6-9]|[2-9]\d)?\d{2})(\/|-|\.)(?:(?:(?:0?[13578]|1[02])\2(?:31))|(?:(?:0?[1,3-9]|1[0-2])\2(29|30))|(?:(?:0?[1-9])|(?:1[0-2]))\2(?:0?[1-9]|1\d|2[0-8])))) ([0-2]?[0-9]\:[0-6][0-9]\:[0-6][0-9]\.[0-9]{3})$";
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

                    if (dateDelimiter == Utility.DateDelimiter.UTCWithDelimiters)
                    {
                        //Example 2015-12-08T15:15:19
                        strFormat = new string[] { "yyyy-MM-dd'T'H:m:s", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd'T'H:m:s'Z'", "yyyy-MM-dd'T'HH:mm:ss'Z'" };

                        dateRegexObj.PerformRegexForDateTimeWithSecondsAsUTCWithDelimiters(dateToClean);
                    }

                    if (dateDelimiter == Utility.DateDelimiter.UTCWithoutDelimiters)
                    {
                        strFormat = new string[] { "yyyyMMdd'T'HHmmss", "yyyyMMdd'T'Hms", "yyyyMd'T'Hms" }; //Example 20151208T151519

                        //TODO: support yyyyMMdd'T'HHmmss.SSSZ with Milliseconds ?!?

                        dateRegexObj.PerformRegexForDateTimeWithSecondsAsUTCWithoutDelimiters(dateToClean);
                    }
                    #endregion

                    CultureInfo culture = null;

                    if (dateFormat == DateFormat.US || dateFormat == DateFormat.SQLServer) //Example 6/15/2009 1:45:30 PM
                    {
                        culture = CultureInfo.CreateSpecificCulture("en-US");
                    }

                    if (dateFormat == DateFormat.Euro) //Example 15/06/2009 13:45:30
                    {
                        culture = CultureInfo.CreateSpecificCulture("es-ES");//Spain
                    }

                    if (dateFormat == DateFormat.China) //Example 2009/6/15 13:45:30
                    {
                        culture = CultureInfo.CreateSpecificCulture("zh-CN");//China
                    }

                    try
                    {
                        value = DateTime.ParseExact(dateToClean, strFormat, culture, DateTimeStyles.None);
                    }
                    catch (FormatException)
                    {
                       throw new Exception("Unable to parse date.");
                    }

                    //SOURCE: https://blog.submain.com/4-common-datetime-mistakes-c-avoid/
                    if (DateTime.Compare(value.ToUniversalTime(), dateMinValue.ToUniversalTime()) < 0) //convert to utc prior to comparison
                    {
                            tmpResult = dateMinValue; //if minimum needs to be applied then apply it.
                    }
                    else //check for maximum
                    {
                        if (DateTime.Compare(value.ToUniversalTime(), dateMaxValue.ToUniversalTime()) > 0)
                        {
                            tmpResult = dateMaxValue;
                        }
                        else
                        {
                            tmpResult = value;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException(dateToClean, ex);
            }
            return tmpResult;
        }

        private void TrackOrThrowException(string valToClean, Exception ex)
        {
            //TODO: apply blacklist to remove potentially malicious characters such as carriage return line feed. Don't want these in the log!
            string exceptionValue = Truncate.TruncateToValidLength(valToClean, 33);

            if (SanitizerApproach == SaniApproach.TrackExceptionsInList)
            {
                SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(SaniTypes.MinMax, exceptionValue));
            }
            else
            {
                throw new SanitizerException("Error reduce to valid MinMax value: " + exceptionValue, ex);
            }
        }
    }//end of class
}//end of namespace
