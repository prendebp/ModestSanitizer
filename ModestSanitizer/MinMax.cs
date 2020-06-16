using System;
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
    ///  ToValidValue (e.g. max value of a number)
    //   Why? To protect against buffer overflow attacks, e.g. if using unsafe keyword: https://stackoverflow.com/questions/9343665/are-buffer-overflow-exploits-possible-in-c
    /// </summary>
    public class MinMax
    {
        private SaniCore SaniCore { get; set; }

        private int TruncateLength { get; set; }
        private SaniTypes SaniType { get; set; }

        public LongType1 LongType { get; set; }
        public DecimalType2 DecimalType { get; set; }
        public IntegerType3 IntegerType { get; set; }
        public BooleanType4 BooleanType { get; set; }
        public DateTimeType5 DateTimeType { get; set; }

        public MinMax(SaniCore saniCore)
        {
            SaniCore = saniCore;

            TruncateLength = 10;
            SaniType = SaniTypes.MinMax;

            LongType = new LongType1(saniCore);
            DecimalType = new DecimalType2(saniCore);
            IntegerType = new IntegerType3(saniCore);
            BooleanType = new BooleanType4(saniCore);
            DateTimeType = new DateTimeType5(saniCore);
        }

        public class LongType1
        {
            private SaniCore SaniCore { get; set; }

            private int TruncateLength { get; set; }
            private SaniTypes SaniType { get; set; }

            public LongType1(SaniCore saniCore)
            {
                SaniCore = saniCore;

                TruncateLength = 10;
                SaniType = SaniTypes.MinMax;
            }

            /// <summary>
            /// ToValidValue - enforce max and min value of a nullable long (SQL Server BigInt)
            /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
            /// </summary>
            /// <param name="longToClean"></param>
            /// <returns></returns>         
            public long? ToValidValue(string longToClean, long longMaxValue, long longMinValue)
            {
                long? tmpResult = 0;

                try
                {
                    if (String.IsNullOrWhiteSpace(longToClean))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
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
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "MinMax: ", "Error long to valid MinMax value: ", longToClean, ex);
                }
                return tmpResult;
            }
        }

        public enum CurrencySeparators
        {
            xCommaxDotx = 1, // default en-US
            xDotxCommax = 2,
            xSpacexDotx = 3,
            xSpacexCommax = 4
        }

        public class DecimalType2
        {
            private SaniCore SaniCore { get; set; }

            private int TruncateLength { get; set; }
            private SaniTypes SaniType { get; set; }

            public DecimalType2(SaniCore saniCore)
            {
                SaniCore = saniCore;

                TruncateLength = 15;
                SaniType = SaniTypes.MinMax;
            }

            /// <summary>
            /// ToValidValue - enforce max and min value of a nullable decimal
            /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
            /// </summary>
            /// <param name="decimalToClean"></param>
            /// <returns></returns>         
            public decimal? ToValidValue(string decimalToClean, decimal decimalMaxValue, decimal decimalMinValue, bool allowNegativeSign, CurrencySeparators currencySeparators = CurrencySeparators.xCommaxDotx)
            {
                decimal? tmpResult = 0;

                try
                {
                    if (String.IsNullOrWhiteSpace(decimalToClean))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
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

                        decimalToClean = SaniCore.NormalizeOrLimit.ToASCIINumbersOnly(decimalToClean, true, true, allowNegativeSign, true);

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
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "MinMax: ", "Error decimal to valid MinMax value: ", decimalToClean, ex);
                }
                return tmpResult;
            }
        }

        //TODO: Create new CurrencyCleanse? To monitor for allowedListed currencies or else log exceptions

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

        public class IntegerType3
        {
            private SaniCore SaniCore { get; set; }

            private int TruncateLength { get; set; }
            private SaniTypes SaniType { get; set; }

            public IntegerType3(SaniCore saniCore)
            {
                SaniCore = saniCore;

                TruncateLength = 10;
                SaniType = SaniTypes.MinMax;
            }

            /// <summary>
            /// ToValidValue - enforce max and min value of a nullable integer
            /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
            /// </summary>
            /// <param name="intToClean"></param>
            /// <returns></returns>   
            public int? ToValidValue(string intToClean, int intMaxValue, int intMinValue)
            {
                int? tmpResult = 0;

                try
                {
                    if (String.IsNullOrWhiteSpace(intToClean))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
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
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "MinMax: ", "Error integer to valid MinMax value: ", intToClean, ex);
                }
                return tmpResult;
            }
        }

        public class BooleanType4
        {
            private SaniCore SaniCore { get; set; }

            private int TruncateLength { get; set; }
            private SaniTypes SaniType { get; set; }

            public BooleanType4(SaniCore saniCore)
            {
                SaniCore = saniCore;

                TruncateLength = 5;
                SaniType = SaniTypes.MinMax;
            }

            /// <summary>
            /// ToValidValue - enforce max and min value of a nullable boolean
            /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
            /// </summary>
            /// <param name="boolToClean"></param>
            /// <returns></returns>   
            public bool? ToValidValue(string boolToClean)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(boolToClean))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        bool value;

                        string truncatedValue = SaniCore.Truncate.ToValidLength(boolToClean, 5);
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
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "MinMax: ", "Error boolean to valid MinMax value: ", boolToClean, ex);
                }
                return tmpResult;
            }
        }

        public enum DateFormat
        {
            None = 0,
            US = 1,
            Euro = 2,
            China = 3,
            SQLServer = 4
        }
        public class DateTimeType5
        {
            private SaniCore SaniCore { get; set; }
            MinMax ThisMinMax { get; set; }

            private int TruncateLength { get; set; }
            private SaniTypes SaniType { get; set; }

            public DateTimeType5(SaniCore saniCore)
            {
                SaniCore = saniCore;

                TruncateLength = 33;
                SaniType = SaniTypes.MinMax;
            }

            /// <summary>
            /// ToValidValueUSDefault - enforce max and min value of a nullable datetime. Default max 1/1/2999 and min 1/1/1753 with ForwardSlash and US Format and no AM/PM.
            /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
            /// </summary>
            /// <param name="decimalToClean"></param>
            /// <returns></returns>         
            public DateTime? ToValidValueUSDefault(string dateToClean, DateUtil.DataType dateDataType)
            {
                return SaniCore.MinMax.DateTimeType.ToValidValue(dateToClean, new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), dateDataType, DateUtil.Delim.ForwardSlash, MinMax.DateFormat.US, false);
            }

            /// <summary>
            /// ToValidValueUSDefault - enforce max and min value of a nullable datetime. Default max 1/1/2999 and min 1/1/1753 with US Format and no AM/PM.
            /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
            /// </summary>
            /// <param name="decimalToClean"></param>
            /// <returns></returns>         
            public DateTime? ToValidValueUSDefault(string dateToClean, DateUtil.DataType dateDataType, DateUtil.Delim dateDelimiter)
            {
                return SaniCore.MinMax.DateTimeType.ToValidValue(dateToClean, new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), dateDataType, dateDelimiter, MinMax.DateFormat.US, false);
            }

            /// <summary>
            /// ToValidValueUSDefault - enforce max and min value of a nullable datetime. Default max 1/1/2999 and min 1/1/1753 with no AM/PM.
            /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
            /// </summary>
            /// <param name="decimalToClean"></param>
            /// <returns></returns>         
            public DateTime? ToValidValueUSDefault(string dateToClean, DateUtil.DataType dateDataType, DateUtil.Delim dateDelimiter, DateFormat dateFormat)
            {
                return SaniCore.MinMax.DateTimeType.ToValidValue(dateToClean, new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), dateDataType, dateDelimiter, dateFormat, false);
            }

            /// <summary>
            /// ToValidValueUSDefault - enforce max and min value of a nullable datetime. Default max 1/1/2999 and min 1/1/1753.
            /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
            /// </summary>
            /// <param name="decimalToClean"></param>
            /// <returns></returns>         
            public DateTime? ToValidValueUSDefault(string dateToClean, DateUtil.DataType dateDataType, DateUtil.Delim dateDelimiter, DateFormat dateFormat, bool expectTrailingAMorPM)
            {
                return SaniCore.MinMax.DateTimeType.ToValidValue(dateToClean, new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), dateDataType, dateDelimiter, dateFormat, expectTrailingAMorPM);
            }
            /// <summary>
            /// ToValidValue - enforce max and min value of a nullable datetime
            /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
            /// </summary>
            /// <param name="dateToClean"></param>
            /// <returns></returns>         
            public DateTime? ToValidValue(string dateToClean, DateTime dateMaxValue, DateTime dateMinValue, DateUtil.DataType dateDataType, DateUtil.Delim dateDelimiter, DateFormat dateFormat, bool expectTrailingAMorPM)
            {
                String[] strFormat = null;
                DateTime? tmpResult = null;

                try
                {
                    if (String.IsNullOrWhiteSpace(dateToClean))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        DateTime value;

                        if (DateTime.Compare(dateMinValue.ToUniversalTime(), dateMaxValue.ToUniversalTime()) > 0)
                        {
                            throw new Exception("Invalid parameters: minimum date cannot be greater than the maximum date.");
                        }

                        if (dateDelimiter == DateUtil.Delim.ForwardSlash)
                        {
                            if (dateToClean.IndexOf(@"/") == -1)
                            {
                                throw new Exception("Invalid date: missing forward slash delimiter.");
                            }
                        }
                        if (dateDelimiter == DateUtil.Delim.Dash)
                        {
                            if (dateToClean.IndexOf(@"-") == -1)
                            {
                                throw new Exception("Invalid date: missing dash delimiter.");
                            }
                        }

                        if (dateDelimiter == DateUtil.Delim.Dot)
                        {
                            if (dateToClean.IndexOf(@".") == -1)
                            {
                                throw new Exception("Invalid date: missing dot delimiter.");
                            }
                        }

                        //This includes Truncate to 33 chars (longest datetime format)
                        dateToClean = SaniCore.NormalizeOrLimit.ToASCIIDateTimesOnly(dateToClean, dateDelimiter, dateDataType, expectTrailingAMorPM);

                        #region Regex checks and strFormat assignment

                        DateRegex dateRegexObj = new DateRegex(SaniCore.CompileRegex);

                        //Perform specific Regex checks where possible after having already normalized the unicode string and reduced it to ASCII-like characters.
                        if ((dateDataType == DateUtil.DataType.Date) && (dateFormat == DateFormat.US)) //Delimiter slash, dash, or dot
                        {
                            strFormat = new string[] { "M/d/yyyy", "MM/dd/yyyy" }; //Example 6/14/2020

                            if (dateDelimiter == DateUtil.Delim.Dot)
                            {
                                strFormat = new string[] { "M.d.yyyy", "MM.dd.yyyy" };
                            }
                            if (dateDelimiter == DateUtil.Delim.Dash)
                            {
                                strFormat = new string[] { "M-d-yyyy", "MM-dd-yyyy" };
                            }

                            dateRegexObj.PerformRegexForDateInUSFormat(dateToClean);
                        }

                        if ((dateDataType == DateUtil.DataType.Date) && (dateFormat == DateFormat.Euro)) //Delimiter slash, dash, or dot
                        {
                            strFormat = new string[] { "d/M/yyyy", "dd/MM/yyyy" }; //Example 28/02/2005

                            if (dateDelimiter == DateUtil.Delim.Dot)
                            {
                                strFormat = new string[] { "d.M.yyyy", "dd.MM.yyyy" };
                            }
                            if (dateDelimiter == DateUtil.Delim.Dash)
                            {
                                strFormat = new string[] { "d-M-yyyy", "dd-MM-yyyy" };
                            }

                            dateRegexObj.PerformRegexForDateInEuroFormat(dateToClean);
                        }

                        if ((dateDataType == DateUtil.DataType.Date) && (dateFormat == DateFormat.China)) //Delimiter slash, dash, or dot
                        {
                            strFormat = new string[] { "yyyy/M/d", "yyyy/MM/dd" }; //Example 2009/6/15

                            if (dateDelimiter == DateUtil.Delim.Dot)
                            {
                                strFormat = new string[] { "yyyy.M.d", "yyyy.MM.dd" };
                            }
                            if (dateDelimiter == DateUtil.Delim.Dash)
                            {
                                strFormat = new string[] { "yyyy-M-d", "yyyy-MM-dd" };
                            }

                            dateRegexObj.PerformRegexForDateInChineseFormat(dateToClean);
                        }

                        //Not the best regex here but we still have DateTime.ParseExact further below.
                        if ((dateDataType == DateUtil.DataType.DateTime) && (dateFormat == DateFormat.US)) //Delimiter slash, dash, or dot
                        {
                            strFormat = null; //Example 02/18/1753 15:15  NOTE: capital H indicates 24-hour time.

                            if (dateDelimiter == DateUtil.Delim.ForwardSlash)
                            {
                                strFormat = new string[] { "M/d/yyyy H:m", "MM/dd/yyyy H:m" };
                            }
                            if (dateDelimiter == DateUtil.Delim.Dot)
                            {
                                strFormat = new string[] { "M.d.yyyy H:m", "MM.dd.yyyy H:m" };
                            }
                            if (dateDelimiter == DateUtil.Delim.Dash)
                            {
                                strFormat = new string[] { "M-d-yyyy H:m", "MM-dd-yyyy H:m" };
                            }

                            dateRegexObj.PerformRegexForDateTimeInUSFormat(dateToClean);
                        }

                        //Not the best regex here but we still have DateTime.ParseExact further below.
                        if ((dateDataType == DateUtil.DataType.DateTimeWithSeconds) && (dateFormat == DateFormat.US) && !(dateDelimiter == DateUtil.Delim.UTCWithDelimiters || dateDelimiter == DateUtil.Delim.UTCWithoutDelimiters || dateDelimiter == DateUtil.Delim.UTCWithDelimitersAndZone)) //Delimiter slash, dash, or dot
                        {
                            strFormat = null; //Example 06/05/2009 15:15:33 or 06/05/2009 03:15:33 PM

                            //Date in US format with single space H:m:ss and with optional AM or PM
                            if (expectTrailingAMorPM == false)
                            {
                                if (dateDelimiter == DateUtil.Delim.ForwardSlash) //NOTE: capital H indicates 24-hour time.
                                {
                                    strFormat = new string[] { "M/d/yyyy H:m:s", "MM/dd/yyyy H:m:s" };
                                }
                                if (dateDelimiter == DateUtil.Delim.Dot)
                                {
                                    strFormat = new string[] { "M.d.yyyy H:m:s", "MM.dd.yyyy H:m:s" };
                                }
                                if (dateDelimiter == DateUtil.Delim.Dash)
                                {
                                    strFormat = new string[] { "M-d-yyyy H:m:s", "MM-dd-yyyy H:m:s" };
                                }
                            }
                            else //expect AM or PM
                            {
                                if (dateDelimiter == DateUtil.Delim.ForwardSlash) //NOTE: capital h indicates regular time not military.
                                {
                                    strFormat = new string[] { "M/d/yyyy h:m:s tt", "M/d/yyyy hh:mm:ss tt", "MM/dd/yyyy h:m:s tt", "MM/dd/yyyy hh:mm:ss tt" };
                                }
                                if (dateDelimiter == DateUtil.Delim.Dot)
                                {
                                    strFormat = new string[] { "M.d.yyyy h:m:s tt", "M.d.yyyy hh:mm:ss tt", "MM.dd.yyyy h:m:s tt", "MM.dd.yyyy hh:mm:ss tt" };
                                }
                                if (dateDelimiter == DateUtil.Delim.Dash)
                                {
                                    strFormat = new string[] { "M-d-yyyy h:m:s tt", "M-d-yyyy hh:mm:ss tt", "MM-dd-yyyy h:m:s tt", "MM-dd-yyyy hh:mm:ss tt" };
                                }
                            }

                            dateRegexObj.PerformRegexForDateTimeWithSecondsInUSFormat(dateToClean, expectTrailingAMorPM);
                        }

                        //Not the best regex here but we still have DateTime.ParseExact further below.
                        if ((dateDataType == DateUtil.DataType.DateTimeWithMilliseconds) && (dateFormat == DateFormat.US)) //Delimiter slash, dash, or dot
                        {
                            strFormat = null; //Example 06/05/2009 15:15:33.001 OR 06/05/2009 03:05:03.003 PM

                            //Date in US format with single space H:m:ss.fff and with optional AM or PM  

                            //NOTE: M = single-digit month is formatted WITHOUT a leading zero. MM = single-digit month is formatted WITH a leading zero.
                            //      H = single-digit hour is formatted WITHOUT a leading zero.  HH = single-digit hour is formatted WITH a leading zero.
                            //      d = single-digit day is formatted WITHOUT a leading zero.   dd = single-digit day is formatted WITH a leading zero.
                            if (expectTrailingAMorPM == false)
                            {
                                if (dateDelimiter == DateUtil.Delim.ForwardSlash) //NOTE: capital H indicates 24-hour time. 
                                {
                                    strFormat = new string[] { "M/d/yyyy H:m:s.fff", "MM/dd/yyyy H:m:s.fff", "MM/dd/yyyy HH:mm:ss.fff", "M/d/yyyy HH:m:s.fff" };
                                }
                                if (dateDelimiter == DateUtil.Delim.Dot)
                                {
                                    strFormat = new string[] { "M.d.yyyy H:m:s.fff", "MM.dd.yyyy H:m:s.fff", "MM.dd.yyyy HH:mm:ss.fff", "M.d.yyyy HH:m:s.fff" };
                                }
                                if (dateDelimiter == DateUtil.Delim.Dash)
                                {
                                    strFormat = new string[] { "M-d-yyyy H:m:s.fff", "MM-dd-yyyy H:m:s.fff", "MM-dd-yyyy HH:mm:ss.fff", "M-d-yyyy HH:m:s.fff" };
                                }
                            }
                            else //expect AM or PM
                            {
                                if (dateDelimiter == DateUtil.Delim.ForwardSlash) //NOTE: capital h indicates regular time not military.
                                {
                                    strFormat = new string[] { "M/d/yyyy h:m:s.fff tt", "M/d/yyyy hh:mm:ss.fff tt", "MM/dd/yyyy h:m:s.fff tt", "MM/dd/yyyy hh:mm:ss.fff tt" };
                                }
                                if (dateDelimiter == DateUtil.Delim.Dot)
                                {
                                    strFormat = new string[] { "M.d.yyyy h:m:s.fff tt", "M.d.yyyy hh:mm:ss.fff tt", "MM.dd.yyyy h:m:s.fff tt", "MM.dd.yyyy hh:mm:ss.fff tt" };
                                }
                                if (dateDelimiter == DateUtil.Delim.Dash)
                                {
                                    strFormat = new string[] { "M-d-yyyy h:m:s.fff tt", "M-d-yyyy hh:mm:ss.fff tt", "MM-dd-yyyy h:m:s.fff tt", "MM-dd-yyyy hh:mm:ss.fff tt" };
                                }
                            }

                            dateRegexObj.PerformRegexForDateTimeWithMillisecondsInUSFormat(dateToClean, expectTrailingAMorPM);
                        }

                        if ((dateDataType == DateUtil.DataType.SQLServerDateTime) && (dateFormat == DateFormat.SQLServer)) //Delimiter slash, dash, or dot
                        {
                            strFormat = strFormat = new string[] { "yyyy-MM-dd H:m:s.fff", "yyyy-MM-dd HH:mm:ss.fff" }; //Example 2019-01-25 16:01:36.000

                            //Date in SQL Server format
                            dateRegexObj.PerformRegexForDateTimeInSQLServerFormat(dateToClean);
                        }

                        if (dateDelimiter == DateUtil.Delim.UTCWithDelimiters)
                        {
                            //Example 2015-12-08T15:15:19
                            strFormat = new string[] { "yyyy-MM-dd'T'H:m:s", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd'T'H:m:s'Z'", "yyyy-MM-dd'T'HH:mm:ss'Z'" };

                            dateRegexObj.PerformRegexForDateTimeWithSecondsAsUTCWithDelimiters(dateToClean);
                        }

                        if (dateDelimiter == DateUtil.Delim.UTCWithDelimitersAndZone)
                        {
                            //Example 2020-06-10T22:03:15-05:00
                            strFormat = new string[] { "yyyy-MM-dd'T'H:m:sK", "yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'H:m:sK'Z'", "yyyy-MM-dd'T'HH:mm:ssK'Z'" };
                            dateRegexObj.PerformRegexForDateTimeWithSecondsAsUTCWithDelimitersAndZone(dateToClean);
                        }

                        if (dateDelimiter == DateUtil.Delim.UTCWithoutDelimiters)
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
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "MinMax: ", "Error datetime to valid MinMax value: ", dateToClean, ex);
                }
                return tmpResult;
            }
        }

    }//end of class
}//end of namespace
