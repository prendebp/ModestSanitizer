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
    ///  FileNameCleanse = 6
    ///  SanitizeViaRegexUsingASCII
    //   Why? To assist with cleaning filenames of invalid or malicious characters such as null bytes or characters that reverse order to Right-To-Left.
    /// </summary>
    public class FileNameCleanse
    {
        private SaniCore SaniCore { get; set; }

        private int TruncateLength { get; set; }
        private SaniTypes SaniType { get; set; }

        public FileNameCleanse(SaniCore saniCore)
        {
            SaniCore = saniCore;

            TruncateLength = 15;
            SaniType = SaniTypes.FileNameCleanse;
        }

        /// <summary>
        /// Sanitize FileName Via Regex.
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
                    throw new Exception("Filename cannot be null or empty.");
                }
                else
                {
                    tmpResult = SaniCore.Truncate.ToValidLength(filename, maxLength);

                    //check for malicious Unicode prior to normalizing and reducing to ASCII-like characters
                    if (ContainsMaliciousCharacters(ref tmpResult))
                    {
                        throw new Exception("Filename contains potentially malicious characters.");
                    }

                    //normalize prior to checking for dot characters to prevent unicode characters similar to dot
                    tmpResult = SaniCore.NormalizeOrLimit.ToASCIIOnly(tmpResult);

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

                    //now apply the regex check after having already normalized the unicode string and reduced it to ASCII-like characters.
                    //This regex will disallow invalid characters within a filename such as ? * : " < > ; | \ / and will not allow a trailing space or dot.
                    string regex2 = @"^(?!^(PRN|AUX|CLOCK\$|NUL|CON|COM\d|LPT\d|\..*)(\..+)?$)[^\x00-\x1f\\?*:\""<>;|\/]+[^*\x00-\x1F\ .]$";

                    bool matchOnWindows = false;
                    if (SaniCore.CompileRegex)
                    {
                        //May cause build to be slower but runtime Regex to be faster . . . let developer choose.
                        matchOnWindows = Regex.IsMatch(tmpResult, regex2, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
                    }
                    else 
                    {
                        matchOnWindows = Regex.IsMatch(tmpResult, regex2, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                    }

                    if (!matchOnWindows)
                    {
                        throw new Exception("Filename is NOT a valid Windows filename.");
                    }

                    //now check for dot and file extensions after having already normalized, etc.
                    string[] arrayOfStr = tmpResult.Split('.');
                    string fileExtensionWithoutTheDot = arrayOfStr[arrayOfStr.Length - 1];
                    string tmpResultFileExtension = "." + fileExtensionWithoutTheDot;

                    if (optionalWhiteListFileExtension != null) //compare exclusive here
                    {
                        //If a whitelist file extension was NOT provided and matched then throw an exception.
                        if (!String.Equals(optionalWhiteListFileExtension, tmpResultFileExtension, StringComparison.OrdinalIgnoreCase))
                        {
                            throw new Exception("Filename extension fails to match the whitelist file extension.");
                        }
                    }
                    else 
                    {
                        //If no whitelist file extension was provided and if blacklist options were flagged true, apply the blacklists                        
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
                SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "FileNameCleanse: ", "Error sanitizing via Regex using ASCII: ", tmpResult, ex);
            }

            return tmpResult;
        }

        private static bool ContainsMaliciousCharacters(ref string tmpResult)
        {
            StringComparison ic = StringComparison.OrdinalIgnoreCase;

            //Prevent null bytes % 00 injected to terminate the filename: secret.doc % 00.pdf
            //Also, assure it doesn't contain U+202E or U+200F characters meant to manipulate Left-To-Right or Right-To-Left order

            int initialLength = tmpResult.Length;

            tmpResult = Replace(tmpResult, "\0", string.Empty, ic); //replace null byte with empty string
            tmpResult = Replace(tmpResult, "\u00A0", string.Empty, ic); //replace non-breaking space with empty string. Regular space U+0020 would be allowed.
            tmpResult = Replace(tmpResult, "\u2B7E", string.Empty, ic); //replace tab with empty string
            tmpResult = Replace(tmpResult, "\u000A", string.Empty, ic); //replace new line with empty string
            tmpResult = Replace(tmpResult, "\u000D", string.Empty, ic); //replace carriage return with empty string
            tmpResult = Replace(tmpResult, "\u2B7F", string.Empty, ic); //replace vertical tab with empty string
            //tmpResult = Replace(tmpResult, "\u005C", string.Empty, ic); //replace reverse solidus or backslash with empty string
            tmpResult = Replace(tmpResult, "\u200B", string.Empty, ic); //replace zero-width space character with empty string
            tmpResult = Replace(tmpResult, "\u2009", string.Empty, ic); //replace thin space with empty string
            tmpResult = Replace(tmpResult, "\u007F", string.Empty, ic); //replace delete with empty string
            tmpResult = Replace(tmpResult, "\u007E", string.Empty, ic); //replace tilde with empty string
            tmpResult = Replace(tmpResult, "\u0000", string.Empty, ic); //replace null byte with empty string
            tmpResult = Replace(tmpResult, "\u202E", string.Empty, ic); //replace Left-To-Right with empty string
            tmpResult = Replace(tmpResult, "\u200F", string.Empty, ic); //replace Right-To-Left with empty string
            tmpResult = Replace(tmpResult, "% 00", string.Empty, ic); //alert on common examples of null bytes used on hacking sites
            tmpResult = Replace(tmpResult, "%00", string.Empty, ic); //alert on common examples of null bytes used on hacking sites
            tmpResult = Replace(tmpResult, "\uFFFD", string.Empty, ic); //replace U+FFFD REPLACEMENT CHARACTER ('�') with empty string
            int finalLength = tmpResult.Length;

            return (finalLength< initialLength);
        }

        private static bool ContainsExecutableExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.OrdinalIgnoreCase; 

            int initialLength = tmpResult.Length;
            tmpResult = Replace(tmpResult,".exe", string.Empty, ic);
            tmpResult = Replace(tmpResult,".bat", string.Empty, ic);
            tmpResult = Replace(tmpResult,".ps1xml", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".ps1", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".ps2xml", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".ps2", string.Empty, ic);//subset second       
            tmpResult = Replace(tmpResult,".rb", string.Empty, ic);//Ruby
            tmpResult = Replace(tmpResult,".go", string.Empty, ic);//Go
            tmpResult = Replace(tmpResult,".jar", string.Empty, ic);//Java
            tmpResult = Replace(tmpResult,".py", string.Empty, ic);//Python
            tmpResult = Replace(tmpResult,".cmd", string.Empty, ic);
            tmpResult = Replace(tmpResult,".lnk", string.Empty, ic);
            tmpResult = Replace(tmpResult,".scr", string.Empty, ic);
            tmpResult = Replace(tmpResult,".pif", string.Empty, ic);//PIF files are executable files known as Program Information Files.   
            tmpResult = Replace(tmpResult,".vbs", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".vbe", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".vb", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".rs", string.Empty, ic);//RUST 
            tmpResult = Replace(tmpResult,".php5", string.Empty, ic);//longer string first-PHP
            tmpResult = Replace(tmpResult,".php3", string.Empty, ic);//longer string first-PHP
            tmpResult = Replace(tmpResult,".php", string.Empty, ic);//subset second-PHP
            tmpResult = Replace(tmpResult,".pl", string.Empty, ic);//Perl
            tmpResult = Replace(tmpResult,".application", string.Empty, ic);
            tmpResult = Replace(tmpResult,".gadget", string.Empty, ic);
            tmpResult = Replace(tmpResult,".wsh", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".wsc", string.Empty, ic);//longer string first-WSC, short name for Windows Script Component  
            tmpResult = Replace(tmpResult,".wsf", string.Empty, ic);//longer string first- A Windows Script File(WSF) is a file type used by the Microsoft Windows Script Host.
            tmpResult = Replace(tmpResult,".ws", string.Empty, ic);//subset second- WS extension contain scripts written in the Jscript and VBScript script languages
            tmpResult = Replace(tmpResult,".scf", string.Empty, ic);//SCF stands for Shell Command File and is a file format that supports a very limited set of Windows Explorer commands
            tmpResult = Replace(tmpResult,".pif", string.Empty, ic);//PIF stands for Program Information File, containing necessary instructions on how a DOS application should be executed in Windows.
            tmpResult = Replace(tmpResult,".com", string.Empty, ic);//A COM file is a type of simple executable file. COM was used as a filename extension for text files containing commands to be issued to the operating system (similar to a batch file).
            tmpResult = Replace(tmpResult,".hta", string.Empty, ic);//HTA is a file extension for an HTML executable file format. HTA files are often used by viruses to update the system registry.
            tmpResult = Replace(tmpResult,".cpl", string.Empty, ic);//CPL file is a control panel item, such as Displays, Mouse, Sound, or Networking, used by the Windows operating system. 
            tmpResult = Replace(tmpResult,".jse", string.Empty, ic);//longer string first-JSE extension contain encrypted source code for scripts written in the JScript programming language
            tmpResult = Replace(tmpResult,".js", string.Empty, ic);//subset second     
            tmpResult = Replace(tmpResult,".psc1", string.Empty, ic);//File created by Windows PowerShell, an advanced shell for Windows; used by the current console for saving and loading specific shell settings.
            tmpResult = Replace(tmpResult,".psc2", string.Empty, ic);
            tmpResult = Replace(tmpResult,".mshxml", string.Empty, ic);
            tmpResult = Replace(tmpResult,".msh1xml", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".msh2xml", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".msh1", string.Empty, ic);//subset second-Microsoft Help Files
            tmpResult = Replace(tmpResult,".msh2", string.Empty, ic);//subset second            
            tmpResult = Replace(tmpResult,".cgi", string.Empty, ic);//CGI file extension is a Common Gateway Interface Script file written in a programming language like C or Perl--can function as executable files.
            tmpResult = Replace(tmpResult,".inf", string.Empty, ic);//INF is a file extension for a plain text file used by Microsoft Windows for the installation of software and drivers.
            tmpResult = Replace(tmpResult,".rar", string.Empty, ic);//RAR files are compressed files created by the WinRAR archiver
            tmpResult = Replace(tmpResult,".msi", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".msc", string.Empty, ic);//longer string first-MSC is a file extension for a Microsoft management console file format used by Microsoft Windows 
            tmpResult = Replace(tmpResult,".m", string.Empty, ic);//MATLAB - subset last
            tmpResult = Replace(tmpResult,".reg", string.Empty, ic);//Registry
            tmpResult = Replace(tmpResult,".cer", string.Empty, ic);//A CER file is a security file provided by a third party Certificate Authority, such as VeriSign or Thwate, that verifies the authenticity of a website.
            tmpResult = Replace(tmpResult,".crt", string.Empty, ic);//CRT is a file extension for a digital certificate file used with a web browser.
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }

        private static bool ContainsWebExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.OrdinalIgnoreCase;

            int initialLength = tmpResult.Length;
            tmpResult = Replace(tmpResult, ".svg", string.Empty, ic);
            tmpResult = Replace(tmpResult, ".phtml", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult, ".pht", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult, ".xhtml", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult, ".html", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult, ".htm", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult, ".xbap", string.Empty, ic);
            tmpResult = Replace(tmpResult, ".xap", string.Empty, ic);
            tmpResult = Replace(tmpResult, ".swf", string.Empty, ic);
            tmpResult = Replace(tmpResult, ".spl", string.Empty, ic);
            tmpResult = Replace(tmpResult, ".xdp", string.Empty, ic);
            tmpResult = Replace(tmpResult, ".jsp", string.Empty, ic);
            tmpResult = Replace(tmpResult, ".htaccess", string.Empty, ic);//longer string first-placed in the root directory of an Apache Web Server website and is processed by the Web server each time a Web page is accessed.
            tmpResult = Replace(tmpResult, ".hta", string.Empty, ic);//subset second-HTA is a file extension for an HTML executable file format. HTA files are often used by viruses to update the system registry.
            tmpResult = Replace(tmpResult, ".ashx", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult, ".aspx", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult, ".asp", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult, ".wsdl", string.Empty, ic);
            tmpResult = Replace(tmpResult, ".asa", string.Empty, ic);//asa file is an optional file that can contain declarations of objects, variables, and methods that can be accessed by every page in an ASP application.
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }
        private static bool ContainsOfficeMacroExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.OrdinalIgnoreCase;

            int initialLength = tmpResult.Length;
            tmpResult = Replace(tmpResult,".docx", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".docm", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".doc", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".xlsb", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".xlsx", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".xlsm", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".xls", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".xltm", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".xltx", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".xlt", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".xlw", string.Empty, ic);
            tmpResult = Replace(tmpResult,".xlam", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".xla", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".dotm", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".dot", string.Empty, ic);//subset second            
            tmpResult = Replace(tmpResult,".xltm", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".xlt", string.Empty, ic);//subset second 
            tmpResult = Replace(tmpResult,".pptx", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".pptm", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".ppt", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".potm", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".pot", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".ppam", string.Empty, ic);
            tmpResult = Replace(tmpResult,".ppsm", string.Empty, ic);
            tmpResult = Replace(tmpResult,".sldm", string.Empty, ic);            
            tmpResult = Replace(tmpResult,".wps", string.Empty, ic);
            tmpResult = Replace(tmpResult,".xps", string.Empty, ic);
            tmpResult = Replace(tmpResult,".ods", string.Empty, ic);
            tmpResult = Replace(tmpResult,".odt", string.Empty, ic);
            tmpResult = Replace(tmpResult,".odp", string.Empty, ic);
            tmpResult = Replace(tmpResult,".mhtml", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".mht", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".slk", string.Empty, ic);           
            tmpResult = Replace(tmpResult,".ppsx", string.Empty, ic);
            tmpResult = Replace(tmpResult,".vsx", string.Empty, ic);
            tmpResult = Replace(tmpResult,".vsw", string.Empty, ic);
            tmpResult = Replace(tmpResult,".vsl", string.Empty, ic);
            tmpResult = Replace(tmpResult,".vtx", string.Empty, ic);
            tmpResult = Replace(tmpResult,".vssm", string.Empty, ic);
            tmpResult = Replace(tmpResult,".vssx", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".vss", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".vstx", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".vstm", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".vst", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".vsdm", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".vsdx", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".vsd", string.Empty, ic);//subset second
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }

        private static bool ContainsPDFFileExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.OrdinalIgnoreCase;

            int initialLength = tmpResult.Length;
            tmpResult = Replace(tmpResult,".pdf", string.Empty, ic);            
            tmpResult = Replace(tmpResult,".xfdf", string.Empty, ic);
            tmpResult = Replace(tmpResult,".fdf", string.Empty, ic);
            tmpResult = Replace(tmpResult,".eps", string.Empty, ic);
            tmpResult = Replace(tmpResult,".prn", string.Empty, ic);
            tmpResult = Replace(tmpResult,".ps", string.Empty, ic);
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }

        private static bool ContainsMediaFileExtensions(ref string tmpResult)
        {
            StringComparison ic = StringComparison.OrdinalIgnoreCase;

            int initialLength = tmpResult.Length;
            tmpResult = Replace(tmpResult,".wmv", string.Empty, ic);
            tmpResult = Replace(tmpResult,".wma", string.Empty, ic);
            tmpResult = Replace(tmpResult,".mov", string.Empty, ic);
            tmpResult = Replace(tmpResult,".mp3", string.Empty, ic);
            tmpResult = Replace(tmpResult,".mp4", string.Empty, ic);
            tmpResult = Replace(tmpResult,".mpa", string.Empty, ic);
            tmpResult = Replace(tmpResult,".m4a", string.Empty, ic);
            tmpResult = Replace(tmpResult,".m4v", string.Empty, ic);
            tmpResult = Replace(tmpResult,".wav", string.Empty, ic);
            tmpResult = Replace(tmpResult,".aiff", string.Empty, ic);//longer string first
            tmpResult = Replace(tmpResult,".aif", string.Empty, ic);//subset second
            tmpResult = Replace(tmpResult,".flv", string.Empty, ic);
            tmpResult = Replace(tmpResult,".f4v", string.Empty, ic);
            tmpResult = Replace(tmpResult,".avi", string.Empty, ic);
            tmpResult = Replace(tmpResult,".mpeg", string.Empty, ic);
            tmpResult = Replace(tmpResult,".mpg", string.Empty, ic);
            tmpResult = Replace(tmpResult,".swf", string.Empty, ic);
            tmpResult = Replace(tmpResult,".asf", string.Empty, ic);
            tmpResult = Replace(tmpResult,".3gp", string.Empty, ic);
            tmpResult = Replace(tmpResult,".3g2", string.Empty, ic);
            tmpResult = Replace(tmpResult,".ram", string.Empty, ic);
            int finalLength = tmpResult.Length;

            return (finalLength < initialLength);
        }

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

    }//end of class
}//end of namespace
