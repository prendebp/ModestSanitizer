using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizer
{
    /// <summary>
    ///  FileNameCleanse = 6
    ///  SanitizeViaRegexUsingASCII
    //   Why? To assist with cleaning filenames of invalid or malicious characters such as null bytes or characters that reverse order to Right-To-Left.
    /// </summary>
    public class FileNameCleanse
    {
        public Truncate Truncate { get; set; }
        public NormalizeOrLimit NormalizeOrLimit { get; set; }
        public SaniApproach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public FileNameCleanse()
        {
        }

        public FileNameCleanse(SaniApproach sanitizerApproach)
        {
            SanitizerApproach = sanitizerApproach;
        }

        public FileNameCleanse(Truncate truncate, NormalizeOrLimit normalizeOrLimit, SaniApproach sanitizerApproach, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            Truncate = truncate;
            NormalizeOrLimit = normalizeOrLimit;
            SaniExceptions = saniExceptions;
        }

        /// <summary>
        /// Sanitize FileName Via Regex. Disallow more than one dot in the filename. 
        /// SOURCE: https://stackoverflow.com/questions/11794144/regular-expression-for-valid-filename
        /// SOURCE: https://stackoverflow.com/questions/6730009/validate-a-file-name-on-windows
        /// SOURCE: https://stackoverflow.com/questions/62771/how-do-i-check-if-a-given-string-is-a-legal-valid-file-name-under-windows#62855
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>   
        public string SanitizeViaRegexUsingASCII(string filename, int maxLength, bool disallowMoreThanOneDot, string optionalWhiteListFileExtension, bool disallowExecutableExtensions, bool disallowWebExtensions, bool disallowOfficeMacroExtensions, bool disallowPDFFileExtensions, bool disallowMediaFileExtensions)
        {
            string tmpResult = String.Empty;

            try
            {
                if (string.IsNullOrWhiteSpace(filename))
                {
                    tmpResult = filename;
                }
                else
                {
                    tmpResult = Truncate.TruncateToValidLength(filename, maxLength);

                    //check for malicious Unicode prior to normalizing and reducing to ASCII-like characters
                    if (ContainsMaliciousCharacters(ref tmpResult))
                    {
                        throw new Exception("Filename contains potentially malicious characters.");
                    }

                    //normalize prior to checking for dot characters to prevent unicode characters similar to dot
                    tmpResult = NormalizeOrLimit.LimitToASCIIOnly(tmpResult);

                    //check for dot characters
                    char dot = '.';
                    int count = 0;
                    foreach (char letter in tmpResult)
                       if (letter == dot) count++;

                    if (disallowMoreThanOneDot)
                    {
                        if (count > 1)
                        {
                            throw new Exception("Filename contains more than one dot character.");
                        }
                    }

                    if (count == 0)
                    {
                        throw new Exception("Filename does NOT contain at least one dot character.");
                    }

                    //now apply the regex check after having already normalized the string and reduced it to ASCII-like characters.
                    string regex2 = @"^(?!^(PRN|AUX|CLOCK\$|NUL|CON|COM\d|LPT\d|\..*)(\..+)?$)[^\x00-\x1f\\?*:\"";|\/]+[^*\x00-\x1F\ .]$";


                    //TODO: optionally allow turning-on RegexOptions.Compiled

                    bool matchOnWindows = Regex.IsMatch(tmpResult, regex2,  RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                    if (!matchOnWindows)
                    {
                        throw new Exception("Filename is NOT a valid Windows filename.");
                    }

                    //now check for common executable extensions after having already normalized, etc.
                    string[] arrayOfStr = tmpResult.Split('.');
                    string fileExtensionWithoutTheDot = arrayOfStr[arrayOfStr.Length - 1];
                    string tmpResultFileExtension = "." + fileExtensionWithoutTheDot;

                    if (optionalWhiteListFileExtension != null) //compare exclusive here
                    {
                        //a whitelist file extension was provided and matched.
                        if (!String.Equals(optionalWhiteListFileExtension, tmpResultFileExtension, StringComparison.OrdinalIgnoreCase))
                        {
                            throw new Exception("Filename extension fails to match the whitelist file extension.");
                        }
                    }
                    else 
                    {
                        //no whitelist file extension was provided so if blacklist options were flagged true, apply the blacklists
                        
                        if (disallowExecutableExtensions && ContainsExecutableExtensions(ref tmpResult))
                        {
                            throw new Exception("Filename contains common executable extensions.");
                        }

                        if (disallowWebExtensions && ContainsWebExtensions(ref tmpResult))
                        {
                            throw new Exception("Filename contains common web extensions.");
                        }
                        
                        if (disallowOfficeMacroExtensions && ContainsOfficeMacroExtensions(ref tmpResult))
                        {
                            throw new Exception("Filename contains office file extensions.");
                        }

                        if (disallowPDFFileExtensions && ContainsPDFFileExtensions(ref tmpResult))
                        {
                            throw new Exception("Filename contains PDF file extensions.");
                        }

                        if (disallowMediaFileExtensions && ContainsMediaFileExtensions(ref tmpResult))
                        {
                            throw new Exception("Filename contains Media file extensions.");
                        }                        
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException("Error sanitizing via Regex using ASCII: ", tmpResult, ex);
            }

            return tmpResult;
        }

        private static bool ContainsMaliciousCharacters(ref string tmpResult)
        {
            //Prevent null bytes % 00 injected to terminate the filename: secret.doc % 00.pdf
            //Also, assure it doesn't contain U+202E or U+200F characters meant to manipulate Left-To-Right or Right-To-Left order

            int initialLength = tmpResult.Length;
            tmpResult = tmpResult.Replace("\0", string.Empty); //replace null byte with empty string
            tmpResult = tmpResult.Replace("\u00A0", string.Empty); //replace non-breaking space with empty string. Regular space U+0020 would be allowed.
            tmpResult = tmpResult.Replace("\u2B7E", string.Empty); //replace tab with empty string
            tmpResult = tmpResult.Replace("\u000A", string.Empty); //replace new line with empty string
            tmpResult = tmpResult.Replace("\u000D", string.Empty); //replace carriage return with empty string
            tmpResult = tmpResult.Replace("\u2B7F", string.Empty); //replace vertical tab with empty string
            tmpResult = tmpResult.Replace("\u005C", string.Empty); //replace reverse solidus or backslash with empty string
            tmpResult = tmpResult.Replace("\u200B", string.Empty); //replace zero-width space character with empty string
            tmpResult = tmpResult.Replace("\u2009", string.Empty); //replace thin space with empty string
            tmpResult = tmpResult.Replace("\u007F", string.Empty); //replace delete with empty string
            tmpResult = tmpResult.Replace("\u007E", string.Empty); //replace tilde with empty string
            tmpResult = tmpResult.Replace("\u003F", string.Empty); //replace question mark with empty string
            tmpResult = tmpResult.Replace("\u0000", string.Empty); //replace null byte with empty string
            tmpResult = tmpResult.Replace("\u202E", string.Empty); //replace Left-To-Right with empty string
            tmpResult = tmpResult.Replace("\u200F", string.Empty); //replace Right-To-Left with empty string
            tmpResult = tmpResult.Replace("% 00", string.Empty); //alert on common examples of null bytes used on hacking sites
            tmpResult = tmpResult.Replace("%00", string.Empty); //alert on common examples of null bytes used on hacking sites
            int finalLength = tmpResult.Length;

            return (finalLength< initialLength);
        }

        private static bool ContainsExecutableExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.InvariantCultureIgnoreCase; //be inclusive when replacing

            //Using InvariantCultureIgnoreCase even though likely working with only ASCII-like characters.
            //If replaece performed with Unicode for some reason the following would apply:
            //Comparing 'Aa'(00 41 00 61) and 'A   a'(00 41 00 00 00 00 00 00 00 61):
            //InvariantCulture: a + ̊ = å
            //so ".xb   ap" should be replaced just as effectively as ".xbap", etc.

            int initialLength = tmpResult.Length;
            tmpResult = Replaece(tmpResult,".exe", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".bat", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ps1", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ps1xml", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ps2", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ps2xml", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".rb", string.Empty, ic);//Ruby
            tmpResult = Replaece(tmpResult,".m", string.Empty, ic);//MATLAB
            tmpResult = Replaece(tmpResult,".go", string.Empty, ic);//golang
            tmpResult = Replaece(tmpResult,".jar", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".py", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".cmd", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".com", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".lnk", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".pif", string.Empty, ic);//PIF files are executable files known as Program Information Files.
            tmpResult = Replaece(tmpResult,".scr", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vb", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vbe", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".js", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vbs", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".rs", string.Empty, ic);//RUST
            tmpResult = Replaece(tmpResult,".wsh", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".php", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".application", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".gadget", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".msi", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ws", string.Empty, ic); //WS extension contain scripts written in the Jscript and VBScript script languages
            tmpResult = Replaece(tmpResult,".wsf", string.Empty, ic);//A Windows Script File(WSF) is a file type used by the Microsoft Windows Script Host.
            tmpResult = Replaece(tmpResult,".scf", string.Empty, ic);//SCF stands for Shell Command File and is a file format that supports a very limited set of Windows Explorer commands
            tmpResult = Replaece(tmpResult,".pif", string.Empty, ic);//PIF stands for Program Information File, containing necessary instructions on how a DOS application should be executed in Windows.
            tmpResult = Replaece(tmpResult,".com", string.Empty, ic);//A COM file is a type of simple executable file. COM was used as a filename extension for text files containing commands to be issued to the operating system (similar to a batch file).
            tmpResult = Replaece(tmpResult,".hta", string.Empty, ic);//HTA is a file extension for an HTML executable file format. HTA files are often used by viruses to update the system registry.
            tmpResult = Replaece(tmpResult,".cpl", string.Empty, ic);//CPL file is a control panel item, such as Displays, Mouse, Sound, or Networking, used by the Windows operating system. 
            tmpResult = Replaece(tmpResult,".msc", string.Empty, ic);//MSC is a file extension for a Microsoft management console file format used by Microsoft Windows 
            tmpResult = Replaece(tmpResult,".jse", string.Empty, ic);//JSE extension contain encrypted source code for scripts written in the JScript programming language
            tmpResult = Replaece(tmpResult,".wsc", string.Empty, ic);//WSC, short name for Windows Script Component       
            tmpResult = Replaece(tmpResult,".psc1", string.Empty, ic);//File created by Windows PowerShell, an advanced shell for Windows; used by the current console for saving and loading specific shell settings.
            tmpResult = Replaece(tmpResult,".psc2", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".msh1", string.Empty, ic);//Microsoft Help Files
            tmpResult = Replaece(tmpResult,".msh2", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mshxml", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".msh1xml", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".msh2xml", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".cgi", string.Empty, ic);//CGI file extension is a Common Gateway Interface Script file written in a programming language like C or Perl--can function as executable files.
            tmpResult = Replaece(tmpResult,".reg", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".inf", string.Empty, ic);//INF is a file extension for a plain text file used by Microsoft Windows for the installation of software and drivers.
            tmpResult = Replaece(tmpResult,".rar", string.Empty, ic);//RAR files are compressed files created by the WinRAR archiver
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }

        private static bool ContainsWebExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.InvariantCultureIgnoreCase; //be inclusive when replacing

            //Using InvariantCultureIgnoreCase even though likely working with only ASCII-like characters.
            //If replaece performed with Unicode for some reason the following would apply:
            //Comparing 'Aa'(00 41 00 61) and 'A   a'(00 41 00 00 00 00 00 00 00 61):
            //InvariantCulture: a + ̊ = å
            //so ".xb   ap" should be replaced just as effectively as ".xbap", etc.

            int initialLength = tmpResult.Length;
            tmpResult = Replaece(tmpResult, ".svg", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".htm", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".html", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".xhtml", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".xbap", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".xap", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".swf", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".spl", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".xdp", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".jsp", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".htaccess", string.Empty, ic);//placed in the root directory of an Apache Web Server website and is processed by the Web server each time a Web page is accessed.
            tmpResult = Replaece(tmpResult, ".phtml", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".asp", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".ashx", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".aspx", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".wsdl", string.Empty, ic);
            tmpResult = Replaece(tmpResult, ".hta", string.Empty, ic); //HTA is a file extension for an HTML executable file format. HTA files are often used by viruses to update the system registry.
            tmpResult = Replaece(tmpResult, ".cgi", string.Empty, ic);//CGI file extension is a Common Gateway Interface Script file written in a programming language like C or Perl--can function as executable files.
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }
        private static bool ContainsOfficeMacroExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.InvariantCultureIgnoreCase; //be inclusive when replacing

            //Using InvariantCultureIgnoreCase even though likely working with only ASCII-like characters.
            //If replaece performed with Unicode for some reason the following would apply:
            //Comparing 'Aa'(00 41 00 61) and 'A   a'(00 41 00 00 00 00 00 00 00 61):
            //InvariantCulture: a + ̊ = å
            //so ".xb   ap" should be replaced just as effectively as ".xbap", etc.

            int initialLength = tmpResult.Length;
            tmpResult = Replaece(tmpResult,".doc", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".docx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xls", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xlsx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".docm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".dotm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xlsm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xltm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xlam", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ppt", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".pptx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".pptm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".potm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ppam", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ppsm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".sldm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vsd", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".wps", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xps", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".odt", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mht", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mhtml", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ods", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xla", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".slk", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xlsb", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xlt", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xltm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xltx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xlw", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".odp", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".pot", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ppsx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vss", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vst", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vsx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vtx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vsdx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vssx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vstx", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vsdm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vssm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vstm", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vsw", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".vsl", string.Empty, ic);
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }

        private static bool ContainsPDFFileExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.InvariantCultureIgnoreCase; //be inclusive when replacing

            //Using InvariantCultureIgnoreCase even though likely working with only ASCII-like characters.
            //If replaece performed with Unicode for some reason the following would apply:
            //Comparing 'Aa'(00 41 00 61) and 'A   a'(00 41 00 00 00 00 00 00 00 61):
            //InvariantCulture: a + ̊ = å
            //so ".xb   ap" should be replaced just as effectively as ".xbap", etc.

            int initialLength = tmpResult.Length;
            tmpResult = Replaece(tmpResult,".pdf", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".fdf", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".xfdf", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ps", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".eps", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".prn", string.Empty, ic);
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }

        private static bool ContainsMediaFileExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.InvariantCultureIgnoreCase; //be inclusive when replacing

            //Using InvariantCultureIgnoreCase even though likely working with only ASCII-like characters.
            //If replaece performed with Unicode for some reason the following would apply:
            //Comparing 'Aa'(00 41 00 61) and 'A   a'(00 41 00 00 00 00 00 00 00 61):
            //InvariantCulture: a + ̊ = å
            //so ".xb   ap" should be replaced just as effectively as ".xbap", etc.

            int initialLength = tmpResult.Length;
            tmpResult = Replaece(tmpResult,".wmv", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mp3", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".wav", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".aif", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".aiff", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mpa", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".m4a", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".wma", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".flv", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".avi", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mov", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mp4", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".m4v", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mpeg", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mpg", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".swf", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".asf", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".3gp", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".ram", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".flv", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".f4v", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".swf", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".mov", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".3gp", string.Empty, ic);
            tmpResult = Replaece(tmpResult,".3g2", string.Empty, ic);
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }

        //SOURCE: https://stackoverflow.com/questions/6275980/string-replace-ignoring-case
        /// <summary>
        /// Returns a new string in which all occurrences of a specified string in the current instance are replaced with another 
        /// specified string according the type of search to use for the specified string.
        /// </summary>
        /// <param name="str">The string performing the replace method.</param>
        /// <param name="oldValue">The string to be replaced.</param>
        /// <param name="newValue">The string replace all occurrences of <paramref name="oldValue"/>. 
        /// If value is equal to <c>null</c>, than all occurrences of <paramref name="oldValue"/> will be removed from the <paramref name="str"/>.</param>
        /// <param name="comparisonType">One of the enumeration values that specifies the rules for the search.</param>
        /// <returns>A string that is equivalent to the current string except that all instances of <paramref name="oldValue"/> are replaced with <paramref name="newValue"/>. 
        /// If <paramref name="oldValue"/> is not found in the current instance, the method returns the current instance unchanged.</returns>
        [DebuggerStepThrough]
        public static string Replaece(string str, string oldValue, string @newValue, StringComparison comparisonType)
        {
            // Check inputs.
            if (str == null)
            {
                // Same as original .NET C# string.Replace behavior.
                throw new ArgumentNullException(nameof(str));
            }
            if (str.Length == 0)
            {
                // Same as original .NET C# string.Replace behavior.
                return str;
            }
            if (oldValue == null)
            {
                // Same as original .NET C# string.Replace behavior.
                throw new ArgumentNullException(nameof(oldValue));
            }
            if (oldValue.Length == 0)
            {
                // Same as original .NET C# string.Replace behavior.
                throw new ArgumentException("String cannot be of zero length.");
            }

            //if (oldValue.Equals(newValue, comparisonType))
            //{
            //This condition has no sense
            //It will prevent method from replacing: "Example", "ExAmPlE", "EXAMPLE" to "example"
            //return str;
            //}
            // Prepare string builder for storing the processed string.
            // Note: StringBuilder has a better performance than String by 30-40%.
            StringBuilder resultStringBuilder = new StringBuilder(str.Length);
            // Analyze the replacement: replace or remove.
            bool isReplacementNullOrEmpty = string.IsNullOrEmpty(@newValue);
            // Replace all values.
            const int valueNotFound = -1;
            int foundAt;
            int startSearchFromIndex = 0;
            while ((foundAt = str.IndexOf(oldValue, startSearchFromIndex, comparisonType)) != valueNotFound)
            {
                // Append all characters until the found replacement.
                int @charsUntilReplacment = foundAt - startSearchFromIndex;
                bool isNothingToAppend = @charsUntilReplacment == 0;
                if (!isNothingToAppend)
                {
                    resultStringBuilder.Append(str, startSearchFromIndex, @charsUntilReplacment);
                }
                // Process the replacement.
                if (!isReplacementNullOrEmpty)
                {
                    resultStringBuilder.Append(@newValue);
                }
                // Prepare start index for the next search.
                // This needed to prevent infinite loop, otherwise method always start search 
                // from the start of the string. For example: if an oldValue == "EXAMPLE", newValue == "example"
                // and comparisonType == "any ignore case" will conquer to replacing:
                // "EXAMPLE" to "example" to "example" to "example" … infinite loop.
                startSearchFromIndex = foundAt + oldValue.Length;
                if (startSearchFromIndex == str.Length)
                {
                    // It is end of the input string: no more space for the next search.
                    // The input string ends with a value that has already been replaced. 
                    // Therefore, the string builder with the result is complete and no further action is required.
                    return resultStringBuilder.ToString();
                }
            }

            // Append the last part to the result.
            int @charsUntilStringEnd = str.Length - startSearchFromIndex;
            resultStringBuilder.Append(str, startSearchFromIndex, @charsUntilStringEnd);

            return resultStringBuilder.ToString();
        }

        private void TrackOrThrowException(string msg, string valToClean, Exception ex)
        {
            string exceptionValue = Truncate.TruncateToValidLength(valToClean, 15); //allow a few more characters than normal for troubleshooting filenames

            if (SanitizerApproach == SaniApproach.TrackExceptionsInList)
            {
                string exceptionMsg = String.Empty;
                if (ex != null && ex.Message!= null)
                {
                    exceptionMsg = ex.Message;
                }

                SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(SaniTypes.FileNameCleanse, "Filename: " + exceptionValue + " Exception: " + exceptionMsg));
            }
            else
            {
                throw new SanitizerException(msg + (exceptionValue ?? String.Empty), ex);
            }
        }

        //TODO: possibly use this for a comparer in a List or Dictionary to apply OrdinalIgnoreCase?!?
        public class FileName : IComparable
        {
            string fname;
            StringComparer comparer;

            public FileName(string name, StringComparer comparer)
            {
                if (String.IsNullOrEmpty(name))
                    throw new ArgumentNullException("name");

                this.fname = name;

                if (comparer != null)
                    this.comparer = comparer;
                else
                    this.comparer = StringComparer.OrdinalIgnoreCase;
            }

            public string Name
            {
                get { return fname; }
            }

            public int CompareTo(object obj)
            {
                if (obj == null) return 1;

                if (!(obj is FileName))
                    return comparer.Compare(this.fname, obj.ToString());
                else
                    return comparer.Compare(this.fname, ((FileName)obj).Name);
            }
        }
    }//end of class
}//end of namespace
