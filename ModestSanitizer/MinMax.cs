using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
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

        public MinMax(Truncate truncate, NormalizeOrLimit normalizeOrLimit, SaniApproach sanitizerApproach, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            Truncate = truncate;
            NormalizeOrLimit = normalizeOrLimit;
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
                    bool isSuccess = long.TryParse(longToClean, out value);
                    if (isSuccess)
                    {
                        if (value < 0)
                        {
                            if (Math.Min(value, longMinValue) == longMinValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = longMinValue;
                            }
                        }
                        else
                        {
                            if (Math.Max(value, longMaxValue) == longMaxValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = longMaxValue;
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
                        if (value < 0)
                        {
                            if (Math.Min(value, decimalMinValue) == decimalMinValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = decimalMinValue;
                            }
                        }
                        else
                        {
                            if (Math.Max(value, decimalMaxValue) == decimalMaxValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = decimalMaxValue;
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
                    bool isSuccess = int.TryParse(intToClean, out value);
                    if (isSuccess)
                    {
                        if (value < 0)
                        {
                            if (Math.Min(value, intMinValue) == intMinValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = intMinValue;
                            }
                        }
                        else
                        {
                            if (Math.Max(value, intMaxValue) == intMaxValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = intMaxValue;
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

//convert to date
//convert to datetime
//change decimal to allow currency and parse it out?!

        private void TrackOrThrowException(string valToClean, Exception ex)
        {
            string exceptionValue = Truncate.TruncateToValidLength(valToClean, 5);

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
