// Generated from CWE List 4.13 (https://cwe.mitre.org/data/index.html)

use std::str::FromStr;

use thiserror::Error;

pub const CWE_5: &'static str =
    "CWE-5: J2EE Misconfiguration: Data Transmission Without Encryption";
pub const CWE_6: &'static str = "CWE-6: J2EE Misconfiguration: Insufficient Session-ID Length";
pub const CWE_7: &'static str = "CWE-7: J2EE Misconfiguration: Missing Custom Error Page";
pub const CWE_8: &'static str = "CWE-8: J2EE Misconfiguration: Entity Bean Declared Remote";
pub const CWE_9: &'static str =
    "CWE-9: J2EE Misconfiguration: Weak Access Permissions for EJB Methods";
pub const CWE_11: &'static str = "CWE-11: ASP.NET Misconfiguration: Creating Debug Binary";
pub const CWE_12: &'static str = "CWE-12: ASP.NET Misconfiguration: Missing Custom Error Page";
pub const CWE_13: &'static str = "CWE-13: ASP.NET Misconfiguration: Password in Configuration File";
pub const CWE_14: &'static str = "CWE-14: Compiler Removal of Code to Clear Buffers";
pub const CWE_15: &'static str = "CWE-15: External Control of System or Configuration Setting";
pub const CWE_20: &'static str = "CWE-20: Improper Input Validation";
pub const CWE_22: &'static str =
    "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')";
pub const CWE_23: &'static str = "CWE-23: Relative Path Traversal";
pub const CWE_24: &'static str = "CWE-24: Path Traversal: '../filedir'";
pub const CWE_25: &'static str = "CWE-25: Path Traversal: '/../filedir'";
pub const CWE_26: &'static str = "CWE-26: Path Traversal: '/dir/../filename'";
pub const CWE_27: &'static str = "CWE-27: Path Traversal: 'dir/../../filename'";
pub const CWE_28: &'static str = "CWE-28: Path Traversal: '..\\filedir'";
pub const CWE_29: &'static str = "CWE-29: Path Traversal: '\\..\\filename'";
pub const CWE_30: &'static str = "CWE-30: Path Traversal: 'dir\\..\\filename'";
pub const CWE_31: &'static str = "CWE-31: Path Traversal: 'dir\\..\\..\\filename'";
pub const CWE_32: &'static str = "CWE-32: Path Traversal: '...' (Triple Dot)";
pub const CWE_33: &'static str = "CWE-33: Path Traversal: '....' (Multiple Dot)";
pub const CWE_34: &'static str = "CWE-34: Path Traversal: '....//'";
pub const CWE_35: &'static str = "CWE-35: Path Traversal: '.../...//'";
pub const CWE_36: &'static str = "CWE-36: Absolute Path Traversal";
pub const CWE_37: &'static str = "CWE-37: Path Traversal: '/absolute/pathname/here'";
pub const CWE_38: &'static str = "CWE-38: Path Traversal: 'absolute\\pathname\\here'";
pub const CWE_39: &'static str = "CWE-39: Path Traversal: 'C:dirname'";
pub const CWE_40: &'static str = "CWE-40: Path Traversal: '\\UNC\\share\\name' (Windows UNC Share)";
pub const CWE_41: &'static str = "CWE-41: Improper Resolution of Path Equivalence";
pub const CWE_42: &'static str = "CWE-42: Path Equivalence: 'filename.' (Trailing Dot)";
pub const CWE_43: &'static str = "CWE-43: Path Equivalence: 'filename....' (Multiple Trailing Dot)";
pub const CWE_44: &'static str = "CWE-44: Path Equivalence: 'file.name' (Internal Dot)";
pub const CWE_45: &'static str = "CWE-45: Path Equivalence: 'file...name' (Multiple Internal Dot)";
pub const CWE_46: &'static str = "CWE-46: Path Equivalence: 'filename ' (Trailing Space)";
pub const CWE_47: &'static str = "CWE-47: Path Equivalence: ' filename' (Leading Space)";
pub const CWE_48: &'static str = "CWE-48: Path Equivalence: 'file name' (Internal Whitespace)";
pub const CWE_49: &'static str = "CWE-49: Path Equivalence: 'filename/' (Trailing Slash)";
pub const CWE_50: &'static str = "CWE-50: Path Equivalence: '//multiple/leading/slash'";
pub const CWE_51: &'static str = "CWE-51: Path Equivalence: '/multiple//internal/slash'";
pub const CWE_52: &'static str = "CWE-52: Path Equivalence: '/multiple/trailing/slash//'";
pub const CWE_53: &'static str = "CWE-53: Path Equivalence: 'multipleinternalbackslash'";
pub const CWE_54: &'static str = "CWE-54: Path Equivalence: 'filedir' (Trailing Backslash)";
pub const CWE_55: &'static str = "CWE-55: Path Equivalence: '/./' (Single Dot Directory)";
pub const CWE_56: &'static str = "CWE-56: Path Equivalence: 'filedir*' (Wildcard)";
pub const CWE_57: &'static str = "CWE-57: Path Equivalence: 'fakedir/../realdir/filename'";
pub const CWE_58: &'static str = "CWE-58: Path Equivalence: Windows 8.3 Filename";
pub const CWE_59: &'static str =
    "CWE-59: Improper Link Resolution Before File Access ('Link Following')";
pub const CWE_61: &'static str = "CWE-61: UNIX Symbolic Link (Symlink) Following";
pub const CWE_62: &'static str = "CWE-62: UNIX Hard Link";
pub const CWE_64: &'static str = "CWE-64: Windows Shortcut Following (.LNK)";
pub const CWE_65: &'static str = "CWE-65: Windows Hard Link";
pub const CWE_66: &'static str =
    "CWE-66: Improper Handling of File Names that Identify Virtual Resources";
pub const CWE_67: &'static str = "CWE-67: Improper Handling of Windows Device Names";
pub const CWE_69: &'static str =
    "CWE-69: Improper Handling of Windows ::DATA Alternate Data Stream";
pub const CWE_72: &'static str =
    "CWE-72: Improper Handling of Apple HFS+ Alternate Data Stream Path";
pub const CWE_73: &'static str = "CWE-73: External Control of File Name or Path";
pub const CWE_74: &'static str = "CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')";
pub const CWE_75: &'static str = "CWE-75: Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)";
pub const CWE_76: &'static str = "CWE-76: Improper Neutralization of Equivalent Special Elements";
pub const CWE_77: &'static str =
    "CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')";
pub const CWE_78: &'static str = "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')";
pub const CWE_79: &'static str =
    "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')";
pub const CWE_80: &'static str =
    "CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)";
pub const CWE_81: &'static str =
    "CWE-81: Improper Neutralization of Script in an Error Message Web Page";
pub const CWE_82: &'static str =
    "CWE-82: Improper Neutralization of Script in Attributes of IMG Tags in a Web Page";
pub const CWE_83: &'static str =
    "CWE-83: Improper Neutralization of Script in Attributes in a Web Page";
pub const CWE_84: &'static str =
    "CWE-84: Improper Neutralization of Encoded URI Schemes in a Web Page";
pub const CWE_85: &'static str = "CWE-85: Doubled Character XSS Manipulations";
pub const CWE_86: &'static str =
    "CWE-86: Improper Neutralization of Invalid Characters in Identifiers in Web Pages";
pub const CWE_87: &'static str = "CWE-87: Improper Neutralization of Alternate XSS Syntax";
pub const CWE_88: &'static str =
    "CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')";
pub const CWE_89: &'static str =
    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')";
pub const CWE_90: &'static str =
    "CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')";
pub const CWE_91: &'static str = "CWE-91: XML Injection (aka Blind XPath Injection)";
pub const CWE_93: &'static str =
    "CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')";
pub const CWE_94: &'static str =
    "CWE-94: Improper Control of Generation of Code ('Code Injection')";
pub const CWE_95: &'static str = "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')";
pub const CWE_96: &'static str = "CWE-96: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')";
pub const CWE_97: &'static str =
    "CWE-97: Improper Neutralization of Server-Side Includes (SSI) Within a Web Page";
pub const CWE_98: &'static str = "CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')";
pub const CWE_99: &'static str =
    "CWE-99: Improper Control of Resource Identifiers ('Resource Injection')";
pub const CWE_102: &'static str = "CWE-102: Struts: Duplicate Validation Forms";
pub const CWE_103: &'static str = "CWE-103: Struts: Incomplete validate() Method Definition";
pub const CWE_104: &'static str = "CWE-104: Struts: Form Bean Does Not Extend Validation Class";
pub const CWE_105: &'static str = "CWE-105: Struts: Form Field Without Validator";
pub const CWE_106: &'static str = "CWE-106: Struts: Plug-in Framework not in Use";
pub const CWE_107: &'static str = "CWE-107: Struts: Unused Validation Form";
pub const CWE_108: &'static str = "CWE-108: Struts: Unvalidated Action Form";
pub const CWE_109: &'static str = "CWE-109: Struts: Validator Turned Off";
pub const CWE_110: &'static str = "CWE-110: Struts: Validator Without Form Field";
pub const CWE_111: &'static str = "CWE-111: Direct Use of Unsafe JNI";
pub const CWE_112: &'static str = "CWE-112: Missing XML Validation";
pub const CWE_113: &'static str = "CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')";
pub const CWE_114: &'static str = "CWE-114: Process Control";
pub const CWE_115: &'static str = "CWE-115: Misinterpretation of Input";
pub const CWE_116: &'static str = "CWE-116: Improper Encoding or Escaping of Output";
pub const CWE_117: &'static str = "CWE-117: Improper Output Neutralization for Logs";
pub const CWE_118: &'static str = "CWE-118: Incorrect Access of Indexable Resource ('Range Error')";
pub const CWE_119: &'static str =
    "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer";
pub const CWE_120: &'static str =
    "CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')";
pub const CWE_121: &'static str = "CWE-121: Stack-based Buffer Overflow";
pub const CWE_122: &'static str = "CWE-122: Heap-based Buffer Overflow";
pub const CWE_123: &'static str = "CWE-123: Write-what-where Condition";
pub const CWE_124: &'static str = "CWE-124: Buffer Underwrite ('Buffer Underflow')";
pub const CWE_125: &'static str = "CWE-125: Out-of-bounds Read";
pub const CWE_126: &'static str = "CWE-126: Buffer Over-read";
pub const CWE_127: &'static str = "CWE-127: Buffer Under-read";
pub const CWE_128: &'static str = "CWE-128: Wrap-around Error";
pub const CWE_129: &'static str = "CWE-129: Improper Validation of Array Index";
pub const CWE_130: &'static str = "CWE-130: Improper Handling of Length Parameter Inconsistency";
pub const CWE_131: &'static str = "CWE-131: Incorrect Calculation of Buffer Size";
pub const CWE_134: &'static str = "CWE-134: Use of Externally-Controlled Format String";
pub const CWE_135: &'static str = "CWE-135: Incorrect Calculation of Multi-Byte String Length";
pub const CWE_138: &'static str = "CWE-138: Improper Neutralization of Special Elements";
pub const CWE_140: &'static str = "CWE-140: Improper Neutralization of Delimiters";
pub const CWE_141: &'static str =
    "CWE-141: Improper Neutralization of Parameter/Argument Delimiters";
pub const CWE_142: &'static str = "CWE-142: Improper Neutralization of Value Delimiters";
pub const CWE_143: &'static str = "CWE-143: Improper Neutralization of Record Delimiters";
pub const CWE_144: &'static str = "CWE-144: Improper Neutralization of Line Delimiters";
pub const CWE_145: &'static str = "CWE-145: Improper Neutralization of Section Delimiters";
pub const CWE_146: &'static str =
    "CWE-146: Improper Neutralization of Expression/Command Delimiters";
pub const CWE_147: &'static str = "CWE-147: Improper Neutralization of Input Terminators";
pub const CWE_148: &'static str = "CWE-148: Improper Neutralization of Input Leaders";
pub const CWE_149: &'static str = "CWE-149: Improper Neutralization of Quoting Syntax";
pub const CWE_150: &'static str =
    "CWE-150: Improper Neutralization of Escape, Meta, or Control Sequences";
pub const CWE_151: &'static str = "CWE-151: Improper Neutralization of Comment Delimiters";
pub const CWE_152: &'static str = "CWE-152: Improper Neutralization of Macro Symbols";
pub const CWE_153: &'static str = "CWE-153: Improper Neutralization of Substitution Characters";
pub const CWE_154: &'static str = "CWE-154: Improper Neutralization of Variable Name Delimiters";
pub const CWE_155: &'static str =
    "CWE-155: Improper Neutralization of Wildcards or Matching Symbols";
pub const CWE_156: &'static str = "CWE-156: Improper Neutralization of Whitespace";
pub const CWE_157: &'static str = "CWE-157: Failure to Sanitize Paired Delimiters";
pub const CWE_158: &'static str = "CWE-158: Improper Neutralization of Null Byte or NUL Character";
pub const CWE_159: &'static str = "CWE-159: Improper Handling of Invalid Use of Special Elements";
pub const CWE_160: &'static str = "CWE-160: Improper Neutralization of Leading Special Elements";
pub const CWE_161: &'static str =
    "CWE-161: Improper Neutralization of Multiple Leading Special Elements";
pub const CWE_162: &'static str = "CWE-162: Improper Neutralization of Trailing Special Elements";
pub const CWE_163: &'static str =
    "CWE-163: Improper Neutralization of Multiple Trailing Special Elements";
pub const CWE_164: &'static str = "CWE-164: Improper Neutralization of Internal Special Elements";
pub const CWE_165: &'static str =
    "CWE-165: Improper Neutralization of Multiple Internal Special Elements";
pub const CWE_166: &'static str = "CWE-166: Improper Handling of Missing Special Element";
pub const CWE_167: &'static str = "CWE-167: Improper Handling of Additional Special Element";
pub const CWE_168: &'static str = "CWE-168: Improper Handling of Inconsistent Special Elements";
pub const CWE_170: &'static str = "CWE-170: Improper Null Termination";
pub const CWE_172: &'static str = "CWE-172: Encoding Error";
pub const CWE_173: &'static str = "CWE-173: Improper Handling of Alternate Encoding";
pub const CWE_174: &'static str = "CWE-174: Double Decoding of the Same Data";
pub const CWE_175: &'static str = "CWE-175: Improper Handling of Mixed Encoding";
pub const CWE_176: &'static str = "CWE-176: Improper Handling of Unicode Encoding";
pub const CWE_177: &'static str = "CWE-177: Improper Handling of URL Encoding (Hex Encoding)";
pub const CWE_178: &'static str = "CWE-178: Improper Handling of Case Sensitivity";
pub const CWE_179: &'static str = "CWE-179: Incorrect Behavior Order: Early Validation";
pub const CWE_180: &'static str = "CWE-180: Incorrect Behavior Order: Validate Before Canonicalize";
pub const CWE_181: &'static str = "CWE-181: Incorrect Behavior Order: Validate Before Filter";
pub const CWE_182: &'static str = "CWE-182: Collapse of Data into Unsafe Value";
pub const CWE_183: &'static str = "CWE-183: Permissive List of Allowed Inputs";
pub const CWE_184: &'static str = "CWE-184: Incomplete List of Disallowed Inputs";
pub const CWE_185: &'static str = "CWE-185: Incorrect Regular Expression";
pub const CWE_186: &'static str = "CWE-186: Overly Restrictive Regular Expression";
pub const CWE_187: &'static str = "CWE-187: Partial String Comparison";
pub const CWE_188: &'static str = "CWE-188: Reliance on Data/Memory Layout";
pub const CWE_190: &'static str = "CWE-190: Integer Overflow or Wraparound";
pub const CWE_191: &'static str = "CWE-191: Integer Underflow (Wrap or Wraparound)";
pub const CWE_192: &'static str = "CWE-192: Integer Coercion Error";
pub const CWE_193: &'static str = "CWE-193: Off-by-one Error";
pub const CWE_194: &'static str = "CWE-194: Unexpected Sign Extension";
pub const CWE_195: &'static str = "CWE-195: Signed to Unsigned Conversion Error";
pub const CWE_196: &'static str = "CWE-196: Unsigned to Signed Conversion Error";
pub const CWE_197: &'static str = "CWE-197: Numeric Truncation Error";
pub const CWE_198: &'static str = "CWE-198: Use of Incorrect Byte Ordering";
pub const CWE_200: &'static str =
    "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor";
pub const CWE_201: &'static str = "CWE-201: Insertion of Sensitive Information Into Sent Data";
pub const CWE_202: &'static str = "CWE-202: Exposure of Sensitive Information Through Data Queries";
pub const CWE_203: &'static str = "CWE-203: Observable Discrepancy";
pub const CWE_204: &'static str = "CWE-204: Observable Response Discrepancy";
pub const CWE_205: &'static str = "CWE-205: Observable Behavioral Discrepancy";
pub const CWE_206: &'static str = "CWE-206: Observable Internal Behavioral Discrepancy";
pub const CWE_207: &'static str =
    "CWE-207: Observable Behavioral Discrepancy With Equivalent Products";
pub const CWE_208: &'static str = "CWE-208: Observable Timing Discrepancy";
pub const CWE_209: &'static str =
    "CWE-209: Generation of Error Message Containing Sensitive Information";
pub const CWE_210: &'static str =
    "CWE-210: Self-generated Error Message Containing Sensitive Information";
pub const CWE_211: &'static str =
    "CWE-211: Externally-Generated Error Message Containing Sensitive Information";
pub const CWE_212: &'static str =
    "CWE-212: Improper Removal of Sensitive Information Before Storage or Transfer";
pub const CWE_213: &'static str =
    "CWE-213: Exposure of Sensitive Information Due to Incompatible Policies";
pub const CWE_214: &'static str =
    "CWE-214: Invocation of Process Using Visible Sensitive Information";
pub const CWE_215: &'static str = "CWE-215: Insertion of Sensitive Information Into Debugging Code";
pub const CWE_219: &'static str = "CWE-219: Storage of File with Sensitive Data Under Web Root";
pub const CWE_220: &'static str = "CWE-220: Storage of File With Sensitive Data Under FTP Root";
pub const CWE_221: &'static str = "CWE-221: Information Loss or Omission";
pub const CWE_222: &'static str = "CWE-222: Truncation of Security-relevant Information";
pub const CWE_223: &'static str = "CWE-223: Omission of Security-relevant Information";
pub const CWE_224: &'static str =
    "CWE-224: Obscured Security-relevant Information by Alternate Name";
pub const CWE_226: &'static str =
    "CWE-226: Sensitive Information in Resource Not Removed Before Reuse";
pub const CWE_228: &'static str = "CWE-228: Improper Handling of Syntactically Invalid Structure";
pub const CWE_229: &'static str = "CWE-229: Improper Handling of Values";
pub const CWE_230: &'static str = "CWE-230: Improper Handling of Missing Values";
pub const CWE_231: &'static str = "CWE-231: Improper Handling of Extra Values";
pub const CWE_232: &'static str = "CWE-232: Improper Handling of Undefined Values";
pub const CWE_233: &'static str = "CWE-233: Improper Handling of Parameters";
pub const CWE_234: &'static str = "CWE-234: Failure to Handle Missing Parameter";
pub const CWE_235: &'static str = "CWE-235: Improper Handling of Extra Parameters";
pub const CWE_236: &'static str = "CWE-236: Improper Handling of Undefined Parameters";
pub const CWE_237: &'static str = "CWE-237: Improper Handling of Structural Elements";
pub const CWE_238: &'static str = "CWE-238: Improper Handling of Incomplete Structural Elements";
pub const CWE_239: &'static str = "CWE-239: Failure to Handle Incomplete Element";
pub const CWE_240: &'static str = "CWE-240: Improper Handling of Inconsistent Structural Elements";
pub const CWE_241: &'static str = "CWE-241: Improper Handling of Unexpected Data Type";
pub const CWE_242: &'static str = "CWE-242: Use of Inherently Dangerous Function";
pub const CWE_243: &'static str =
    "CWE-243: Creation of chroot Jail Without Changing Working Directory";
pub const CWE_244: &'static str =
    "CWE-244: Improper Clearing of Heap Memory Before Release ('Heap Inspection')";
pub const CWE_245: &'static str = "CWE-245: J2EE Bad Practices: Direct Management of Connections";
pub const CWE_246: &'static str = "CWE-246: J2EE Bad Practices: Direct Use of Sockets";
pub const CWE_248: &'static str = "CWE-248: Uncaught Exception";
pub const CWE_250: &'static str = "CWE-250: Execution with Unnecessary Privileges";
pub const CWE_252: &'static str = "CWE-252: Unchecked Return Value";
pub const CWE_253: &'static str = "CWE-253: Incorrect Check of Function Return Value";
pub const CWE_256: &'static str = "CWE-256: Plaintext Storage of a Password";
pub const CWE_257: &'static str = "CWE-257: Storing Passwords in a Recoverable Format";
pub const CWE_258: &'static str = "CWE-258: Empty Password in Configuration File";
pub const CWE_259: &'static str = "CWE-259: Use of Hard-coded Password";
pub const CWE_260: &'static str = "CWE-260: Password in Configuration File";
pub const CWE_261: &'static str = "CWE-261: Weak Encoding for Password";
pub const CWE_262: &'static str = "CWE-262: Not Using Password Aging";
pub const CWE_263: &'static str = "CWE-263: Password Aging with Long Expiration";
pub const CWE_266: &'static str = "CWE-266: Incorrect Privilege Assignment";
pub const CWE_267: &'static str = "CWE-267: Privilege Defined With Unsafe Actions";
pub const CWE_268: &'static str = "CWE-268: Privilege Chaining";
pub const CWE_269: &'static str = "CWE-269: Improper Privilege Management";
pub const CWE_270: &'static str = "CWE-270: Privilege Context Switching Error";
pub const CWE_271: &'static str = "CWE-271: Privilege Dropping / Lowering Errors";
pub const CWE_272: &'static str = "CWE-272: Least Privilege Violation";
pub const CWE_273: &'static str = "CWE-273: Improper Check for Dropped Privileges";
pub const CWE_274: &'static str = "CWE-274: Improper Handling of Insufficient Privileges";
pub const CWE_276: &'static str = "CWE-276: Incorrect Default Permissions";
pub const CWE_277: &'static str = "CWE-277: Insecure Inherited Permissions";
pub const CWE_278: &'static str = "CWE-278: Insecure Preserved Inherited Permissions";
pub const CWE_279: &'static str = "CWE-279: Incorrect Execution-Assigned Permissions";
pub const CWE_280: &'static str =
    "CWE-280: Improper Handling of Insufficient Permissions or Privileges ";
pub const CWE_281: &'static str = "CWE-281: Improper Preservation of Permissions";
pub const CWE_282: &'static str = "CWE-282: Improper Ownership Management";
pub const CWE_283: &'static str = "CWE-283: Unverified Ownership";
pub const CWE_284: &'static str = "CWE-284: Improper Access Control";
pub const CWE_285: &'static str = "CWE-285: Improper Authorization";
pub const CWE_286: &'static str = "CWE-286: Incorrect User Management";
pub const CWE_287: &'static str = "CWE-287: Improper Authentication";
pub const CWE_288: &'static str =
    "CWE-288: Authentication Bypass Using an Alternate Path or Channel";
pub const CWE_289: &'static str = "CWE-289: Authentication Bypass by Alternate Name";
pub const CWE_290: &'static str = "CWE-290: Authentication Bypass by Spoofing";
pub const CWE_291: &'static str = "CWE-291: Reliance on IP Address for Authentication";
pub const CWE_293: &'static str = "CWE-293: Using Referer Field for Authentication";
pub const CWE_294: &'static str = "CWE-294: Authentication Bypass by Capture-replay";
pub const CWE_295: &'static str = "CWE-295: Improper Certificate Validation";
pub const CWE_296: &'static str = "CWE-296: Improper Following of a Certificate's Chain of Trust";
pub const CWE_297: &'static str = "CWE-297: Improper Validation of Certificate with Host Mismatch";
pub const CWE_298: &'static str = "CWE-298: Improper Validation of Certificate Expiration";
pub const CWE_299: &'static str = "CWE-299: Improper Check for Certificate Revocation";
pub const CWE_300: &'static str = "CWE-300: Channel Accessible by Non-Endpoint";
pub const CWE_301: &'static str = "CWE-301: Reflection Attack in an Authentication Protocol";
pub const CWE_302: &'static str = "CWE-302: Authentication Bypass by Assumed-Immutable Data";
pub const CWE_303: &'static str = "CWE-303: Incorrect Implementation of Authentication Algorithm";
pub const CWE_304: &'static str = "CWE-304: Missing Critical Step in Authentication";
pub const CWE_305: &'static str = "CWE-305: Authentication Bypass by Primary Weakness";
pub const CWE_306: &'static str = "CWE-306: Missing Authentication for Critical Function";
pub const CWE_307: &'static str =
    "CWE-307: Improper Restriction of Excessive Authentication Attempts";
pub const CWE_308: &'static str = "CWE-308: Use of Single-factor Authentication";
pub const CWE_309: &'static str = "CWE-309: Use of Password System for Primary Authentication";
pub const CWE_311: &'static str = "CWE-311: Missing Encryption of Sensitive Data";
pub const CWE_312: &'static str = "CWE-312: Cleartext Storage of Sensitive Information";
pub const CWE_313: &'static str = "CWE-313: Cleartext Storage in a File or on Disk";
pub const CWE_314: &'static str = "CWE-314: Cleartext Storage in the Registry";
pub const CWE_315: &'static str = "CWE-315: Cleartext Storage of Sensitive Information in a Cookie";
pub const CWE_316: &'static str = "CWE-316: Cleartext Storage of Sensitive Information in Memory";
pub const CWE_317: &'static str = "CWE-317: Cleartext Storage of Sensitive Information in GUI";
pub const CWE_318: &'static str =
    "CWE-318: Cleartext Storage of Sensitive Information in Executable";
pub const CWE_319: &'static str = "CWE-319: Cleartext Transmission of Sensitive Information";
pub const CWE_321: &'static str = "CWE-321: Use of Hard-coded Cryptographic Key";
pub const CWE_322: &'static str = "CWE-322: Key Exchange without Entity Authentication";
pub const CWE_323: &'static str = "CWE-323: Reusing a Nonce, Key Pair in Encryption";
pub const CWE_324: &'static str = "CWE-324: Use of a Key Past its Expiration Date";
pub const CWE_325: &'static str = "CWE-325: Missing Cryptographic Step";
pub const CWE_326: &'static str = "CWE-326: Inadequate Encryption Strength";
pub const CWE_327: &'static str = "CWE-327: Use of a Broken or Risky Cryptographic Algorithm";
pub const CWE_328: &'static str = "CWE-328: Use of Weak Hash";
pub const CWE_329: &'static str = "CWE-329: Generation of Predictable IV with CBC Mode";
pub const CWE_330: &'static str = "CWE-330: Use of Insufficiently Random Values";
pub const CWE_331: &'static str = "CWE-331: Insufficient Entropy";
pub const CWE_332: &'static str = "CWE-332: Insufficient Entropy in PRNG";
pub const CWE_333: &'static str = "CWE-333: Improper Handling of Insufficient Entropy in TRNG";
pub const CWE_334: &'static str = "CWE-334: Small Space of Random Values";
pub const CWE_335: &'static str =
    "CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)";
pub const CWE_336: &'static str = "CWE-336: Same Seed in Pseudo-Random Number Generator (PRNG)";
pub const CWE_337: &'static str =
    "CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)";
pub const CWE_338: &'static str =
    "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)";
pub const CWE_339: &'static str = "CWE-339: Small Seed Space in PRNG";
pub const CWE_340: &'static str = "CWE-340: Generation of Predictable Numbers or Identifiers";
pub const CWE_341: &'static str = "CWE-341: Predictable from Observable State";
pub const CWE_342: &'static str = "CWE-342: Predictable Exact Value from Previous Values";
pub const CWE_343: &'static str = "CWE-343: Predictable Value Range from Previous Values";
pub const CWE_344: &'static str = "CWE-344: Use of Invariant Value in Dynamically Changing Context";
pub const CWE_345: &'static str = "CWE-345: Insufficient Verification of Data Authenticity";
pub const CWE_346: &'static str = "CWE-346: Origin Validation Error";
pub const CWE_347: &'static str = "CWE-347: Improper Verification of Cryptographic Signature";
pub const CWE_348: &'static str = "CWE-348: Use of Less Trusted Source";
pub const CWE_349: &'static str =
    "CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data";
pub const CWE_350: &'static str =
    "CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action";
pub const CWE_351: &'static str = "CWE-351: Insufficient Type Distinction";
pub const CWE_352: &'static str = "CWE-352: Cross-Site Request Forgery (CSRF)";
pub const CWE_353: &'static str = "CWE-353: Missing Support for Integrity Check";
pub const CWE_354: &'static str = "CWE-354: Improper Validation of Integrity Check Value";
pub const CWE_356: &'static str = "CWE-356: Product UI does not Warn User of Unsafe Actions";
pub const CWE_357: &'static str = "CWE-357: Insufficient UI Warning of Dangerous Operations";
pub const CWE_358: &'static str = "CWE-358: Improperly Implemented Security Check for Standard";
pub const CWE_359: &'static str =
    "CWE-359: Exposure of Private Personal Information to an Unauthorized Actor";
pub const CWE_360: &'static str = "CWE-360: Trust of System Event Data";
pub const CWE_362: &'static str = "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')";
pub const CWE_363: &'static str = "CWE-363: Race Condition Enabling Link Following";
pub const CWE_364: &'static str = "CWE-364: Signal Handler Race Condition";
pub const CWE_366: &'static str = "CWE-366: Race Condition within a Thread";
pub const CWE_367: &'static str = "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition";
pub const CWE_368: &'static str = "CWE-368: Context Switching Race Condition";
pub const CWE_369: &'static str = "CWE-369: Divide By Zero";
pub const CWE_370: &'static str =
    "CWE-370: Missing Check for Certificate Revocation after Initial Check";
pub const CWE_372: &'static str = "CWE-372: Incomplete Internal State Distinction";
pub const CWE_374: &'static str = "CWE-374: Passing Mutable Objects to an Untrusted Method";
pub const CWE_375: &'static str = "CWE-375: Returning a Mutable Object to an Untrusted Caller";
pub const CWE_377: &'static str = "CWE-377: Insecure Temporary File";
pub const CWE_378: &'static str = "CWE-378: Creation of Temporary File With Insecure Permissions";
pub const CWE_379: &'static str =
    "CWE-379: Creation of Temporary File in Directory with Insecure Permissions";
pub const CWE_382: &'static str = "CWE-382: J2EE Bad Practices: Use of System.exit()";
pub const CWE_383: &'static str = "CWE-383: J2EE Bad Practices: Direct Use of Threads";
pub const CWE_384: &'static str = "CWE-384: Session Fixation";
pub const CWE_385: &'static str = "CWE-385: Covert Timing Channel";
pub const CWE_386: &'static str = "CWE-386: Symbolic Name not Mapping to Correct Object";
pub const CWE_390: &'static str = "CWE-390: Detection of Error Condition Without Action";
pub const CWE_391: &'static str = "CWE-391: Unchecked Error Condition";
pub const CWE_392: &'static str = "CWE-392: Missing Report of Error Condition";
pub const CWE_393: &'static str = "CWE-393: Return of Wrong Status Code";
pub const CWE_394: &'static str = "CWE-394: Unexpected Status Code or Return Value";
pub const CWE_395: &'static str =
    "CWE-395: Use of NullPointerException Catch to Detect NULL Pointer Dereference";
pub const CWE_396: &'static str = "CWE-396: Declaration of Catch for Generic Exception";
pub const CWE_397: &'static str = "CWE-397: Declaration of Throws for Generic Exception";
pub const CWE_400: &'static str = "CWE-400: Uncontrolled Resource Consumption";
pub const CWE_401: &'static str = "CWE-401: Missing Release of Memory after Effective Lifetime";
pub const CWE_402: &'static str =
    "CWE-402: Transmission of Private Resources into a New Sphere ('Resource Leak')";
pub const CWE_403: &'static str =
    "CWE-403: Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')";
pub const CWE_404: &'static str = "CWE-404: Improper Resource Shutdown or Release";
pub const CWE_405: &'static str = "CWE-405: Asymmetric Resource Consumption (Amplification)";
pub const CWE_406: &'static str =
    "CWE-406: Insufficient Control of Network Message Volume (Network Amplification)";
pub const CWE_407: &'static str = "CWE-407: Inefficient Algorithmic Complexity";
pub const CWE_408: &'static str = "CWE-408: Incorrect Behavior Order: Early Amplification";
pub const CWE_409: &'static str =
    "CWE-409: Improper Handling of Highly Compressed Data (Data Amplification)";
pub const CWE_410: &'static str = "CWE-410: Insufficient Resource Pool";
pub const CWE_412: &'static str = "CWE-412: Unrestricted Externally Accessible Lock";
pub const CWE_413: &'static str = "CWE-413: Improper Resource Locking";
pub const CWE_414: &'static str = "CWE-414: Missing Lock Check";
pub const CWE_415: &'static str = "CWE-415: Double Free";
pub const CWE_416: &'static str = "CWE-416: Use After Free";
pub const CWE_419: &'static str = "CWE-419: Unprotected Primary Channel";
pub const CWE_420: &'static str = "CWE-420: Unprotected Alternate Channel";
pub const CWE_421: &'static str = "CWE-421: Race Condition During Access to Alternate Channel";
pub const CWE_422: &'static str = "CWE-422: Unprotected Windows Messaging Channel ('Shatter')";
pub const CWE_424: &'static str = "CWE-424: Improper Protection of Alternate Path";
pub const CWE_425: &'static str = "CWE-425: Direct Request ('Forced Browsing')";
pub const CWE_426: &'static str = "CWE-426: Untrusted Search Path";
pub const CWE_427: &'static str = "CWE-427: Uncontrolled Search Path Element";
pub const CWE_428: &'static str = "CWE-428: Unquoted Search Path or Element";
pub const CWE_430: &'static str = "CWE-430: Deployment of Wrong Handler";
pub const CWE_431: &'static str = "CWE-431: Missing Handler";
pub const CWE_432: &'static str =
    "CWE-432: Dangerous Signal Handler not Disabled During Sensitive Operations";
pub const CWE_433: &'static str = "CWE-433: Unparsed Raw Web Content Delivery";
pub const CWE_434: &'static str = "CWE-434: Unrestricted Upload of File with Dangerous Type";
pub const CWE_435: &'static str =
    "CWE-435: Improper Interaction Between Multiple Correctly-Behaving Entities";
pub const CWE_436: &'static str = "CWE-436: Interpretation Conflict";
pub const CWE_437: &'static str = "CWE-437: Incomplete Model of Endpoint Features";
pub const CWE_439: &'static str = "CWE-439: Behavioral Change in New Version or Environment";
pub const CWE_440: &'static str = "CWE-440: Expected Behavior Violation";
pub const CWE_441: &'static str = "CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')";
pub const CWE_444: &'static str =
    "CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')";
pub const CWE_446: &'static str = "CWE-446: UI Discrepancy for Security Feature";
pub const CWE_447: &'static str = "CWE-447: Unimplemented or Unsupported Feature in UI";
pub const CWE_448: &'static str = "CWE-448: Obsolete Feature in UI";
pub const CWE_449: &'static str = "CWE-449: The UI Performs the Wrong Action";
pub const CWE_450: &'static str = "CWE-450: Multiple Interpretations of UI Input";
pub const CWE_451: &'static str =
    "CWE-451: User Interface (UI) Misrepresentation of Critical Information";
pub const CWE_453: &'static str = "CWE-453: Insecure Default Variable Initialization";
pub const CWE_454: &'static str =
    "CWE-454: External Initialization of Trusted Variables or Data Stores";
pub const CWE_455: &'static str = "CWE-455: Non-exit on Failed Initialization";
pub const CWE_456: &'static str = "CWE-456: Missing Initialization of a Variable";
pub const CWE_457: &'static str = "CWE-457: Use of Uninitialized Variable";
pub const CWE_459: &'static str = "CWE-459: Incomplete Cleanup";
pub const CWE_460: &'static str = "CWE-460: Improper Cleanup on Thrown Exception";
pub const CWE_462: &'static str = "CWE-462: Duplicate Key in Associative List (Alist)";
pub const CWE_463: &'static str = "CWE-463: Deletion of Data Structure Sentinel";
pub const CWE_464: &'static str = "CWE-464: Addition of Data Structure Sentinel";
pub const CWE_466: &'static str = "CWE-466: Return of Pointer Value Outside of Expected Range";
pub const CWE_467: &'static str = "CWE-467: Use of sizeof() on a Pointer Type";
pub const CWE_468: &'static str = "CWE-468: Incorrect Pointer Scaling";
pub const CWE_469: &'static str = "CWE-469: Use of Pointer Subtraction to Determine Size";
pub const CWE_470: &'static str =
    "CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')";
pub const CWE_471: &'static str = "CWE-471: Modification of Assumed-Immutable Data (MAID)";
pub const CWE_472: &'static str = "CWE-472: External Control of Assumed-Immutable Web Parameter";
pub const CWE_473: &'static str = "CWE-473: PHP External Variable Modification";
pub const CWE_474: &'static str = "CWE-474: Use of Function with Inconsistent Implementations";
pub const CWE_475: &'static str = "CWE-475: Undefined Behavior for Input to API";
pub const CWE_476: &'static str = "CWE-476: NULL Pointer Dereference";
pub const CWE_477: &'static str = "CWE-477: Use of Obsolete Function";
pub const CWE_478: &'static str = "CWE-478: Missing Default Case in Multiple Condition Expression";
pub const CWE_479: &'static str = "CWE-479: Signal Handler Use of a Non-reentrant Function";
pub const CWE_480: &'static str = "CWE-480: Use of Incorrect Operator";
pub const CWE_481: &'static str = "CWE-481: Assigning instead of Comparing";
pub const CWE_482: &'static str = "CWE-482: Comparing instead of Assigning";
pub const CWE_483: &'static str = "CWE-483: Incorrect Block Delimitation";
pub const CWE_484: &'static str = "CWE-484: Omitted Break Statement in Switch";
pub const CWE_486: &'static str = "CWE-486: Comparison of Classes by Name";
pub const CWE_487: &'static str = "CWE-487: Reliance on Package-level Scope";
pub const CWE_488: &'static str = "CWE-488: Exposure of Data Element to Wrong Session";
pub const CWE_489: &'static str = "CWE-489: Active Debug Code";
pub const CWE_491: &'static str =
    "CWE-491: Public cloneable() Method Without Final ('Object Hijack')";
pub const CWE_492: &'static str = "CWE-492: Use of Inner Class Containing Sensitive Data";
pub const CWE_493: &'static str = "CWE-493: Critical Public Variable Without Final Modifier";
pub const CWE_494: &'static str = "CWE-494: Download of Code Without Integrity Check";
pub const CWE_495: &'static str = "CWE-495: Private Data Structure Returned From A Public Method";
pub const CWE_496: &'static str = "CWE-496: Public Data Assigned to Private Array-Typed Field";
pub const CWE_497: &'static str =
    "CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere";
pub const CWE_498: &'static str = "CWE-498: Cloneable Class Containing Sensitive Information";
pub const CWE_499: &'static str = "CWE-499: Serializable Class Containing Sensitive Data";
pub const CWE_500: &'static str = "CWE-500: Public Static Field Not Marked Final";
pub const CWE_501: &'static str = "CWE-501: Trust Boundary Violation";
pub const CWE_502: &'static str = "CWE-502: Deserialization of Untrusted Data";
pub const CWE_506: &'static str = "CWE-506: Embedded Malicious Code";
pub const CWE_507: &'static str = "CWE-507: Trojan Horse";
pub const CWE_508: &'static str = "CWE-508: Non-Replicating Malicious Code";
pub const CWE_509: &'static str = "CWE-509: Replicating Malicious Code (Virus or Worm)";
pub const CWE_510: &'static str = "CWE-510: Trapdoor";
pub const CWE_511: &'static str = "CWE-511: Logic/Time Bomb";
pub const CWE_512: &'static str = "CWE-512: Spyware";
pub const CWE_514: &'static str = "CWE-514: Covert Channel";
pub const CWE_515: &'static str = "CWE-515: Covert Storage Channel";
pub const CWE_520: &'static str = "CWE-520: .NET Misconfiguration: Use of Impersonation";
pub const CWE_521: &'static str = "CWE-521: Weak Password Requirements";
pub const CWE_522: &'static str = "CWE-522: Insufficiently Protected Credentials";
pub const CWE_523: &'static str = "CWE-523: Unprotected Transport of Credentials";
pub const CWE_524: &'static str = "CWE-524: Use of Cache Containing Sensitive Information";
pub const CWE_525: &'static str =
    "CWE-525: Use of Web Browser Cache Containing Sensitive Information";
pub const CWE_526: &'static str =
    "CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable";
pub const CWE_527: &'static str =
    "CWE-527: Exposure of Version-Control Repository to an Unauthorized Control Sphere";
pub const CWE_528: &'static str =
    "CWE-528: Exposure of Core Dump File to an Unauthorized Control Sphere";
pub const CWE_529: &'static str =
    "CWE-529: Exposure of Access Control List Files to an Unauthorized Control Sphere";
pub const CWE_530: &'static str =
    "CWE-530: Exposure of Backup File to an Unauthorized Control Sphere";
pub const CWE_531: &'static str = "CWE-531: Inclusion of Sensitive Information in Test Code";
pub const CWE_532: &'static str = "CWE-532: Insertion of Sensitive Information into Log File";
pub const CWE_535: &'static str = "CWE-535: Exposure of Information Through Shell Error Message";
pub const CWE_536: &'static str =
    "CWE-536: Servlet Runtime Error Message Containing Sensitive Information";
pub const CWE_537: &'static str =
    "CWE-537: Java Runtime Error Message Containing Sensitive Information";
pub const CWE_538: &'static str =
    "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory";
pub const CWE_539: &'static str =
    "CWE-539: Use of Persistent Cookies Containing Sensitive Information";
pub const CWE_540: &'static str = "CWE-540: Inclusion of Sensitive Information in Source Code";
pub const CWE_541: &'static str = "CWE-541: Inclusion of Sensitive Information in an Include File";
pub const CWE_543: &'static str =
    "CWE-543: Use of Singleton Pattern Without Synchronization in a Multithreaded Context";
pub const CWE_544: &'static str = "CWE-544: Missing Standardized Error Handling Mechanism";
pub const CWE_546: &'static str = "CWE-546: Suspicious Comment";
pub const CWE_547: &'static str = "CWE-547: Use of Hard-coded, Security-relevant pub constants";
pub const CWE_548: &'static str = "CWE-548: Exposure of Information Through Directory Listing";
pub const CWE_549: &'static str = "CWE-549: Missing Password Field Masking";
pub const CWE_550: &'static str =
    "CWE-550: Server-generated Error Message Containing Sensitive Information";
pub const CWE_551: &'static str =
    "CWE-551: Incorrect Behavior Order: Authorization Before Parsing and Canonicalization";
pub const CWE_552: &'static str = "CWE-552: Files or Directories Accessible to External Parties";
pub const CWE_553: &'static str = "CWE-553: Command Shell in Externally Accessible Directory";
pub const CWE_554: &'static str =
    "CWE-554: ASP.NET Misconfiguration: Not Using Input Validation Framework";
pub const CWE_555: &'static str =
    "CWE-555: J2EE Misconfiguration: Plaintext Password in Configuration File";
pub const CWE_556: &'static str =
    "CWE-556: ASP.NET Misconfiguration: Use of Identity Impersonation";
pub const CWE_558: &'static str = "CWE-558: Use of getlogin() in Multithreaded Application";
pub const CWE_560: &'static str = "CWE-560: Use of umask() with chmod-style Argument";
pub const CWE_561: &'static str = "CWE-561: Dead Code";
pub const CWE_562: &'static str = "CWE-562: Return of Stack Variable Address";
pub const CWE_563: &'static str = "CWE-563: Assignment to Variable without Use";
pub const CWE_564: &'static str = "CWE-564: SQL Injection: Hibernate";
pub const CWE_565: &'static str =
    "CWE-565: Reliance on Cookies without Validation and Integrity Checking";
pub const CWE_566: &'static str =
    "CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key";
pub const CWE_567: &'static str =
    "CWE-567: Unsynchronized Access to Shared Data in a Multithreaded Context";
pub const CWE_568: &'static str = "CWE-568: finalize() Method Without super.finalize()";
pub const CWE_570: &'static str = "CWE-570: Expression is Always False";
pub const CWE_571: &'static str = "CWE-571: Expression is Always True";
pub const CWE_572: &'static str = "CWE-572: Call to Thread run() instead of start()";
pub const CWE_573: &'static str = "CWE-573: Improper Following of Specification by Caller";
pub const CWE_574: &'static str = "CWE-574: EJB Bad Practices: Use of Synchronization Primitives";
pub const CWE_575: &'static str = "CWE-575: EJB Bad Practices: Use of AWT Swing";
pub const CWE_576: &'static str = "CWE-576: EJB Bad Practices: Use of Java I/O";
pub const CWE_577: &'static str = "CWE-577: EJB Bad Practices: Use of Sockets";
pub const CWE_578: &'static str = "CWE-578: EJB Bad Practices: Use of Class Loader";
pub const CWE_579: &'static str =
    "CWE-579: J2EE Bad Practices: Non-serializable Object Stored in Session";
pub const CWE_580: &'static str = "CWE-580: clone() Method Without super.clone()";
pub const CWE_581: &'static str =
    "CWE-581: Object Model Violation: Just One of Equals and Hashcode Defined";
pub const CWE_582: &'static str = "CWE-582: Array Declared Public, Final, and Static";
pub const CWE_583: &'static str = "CWE-583: finalize() Method Declared Public";
pub const CWE_584: &'static str = "CWE-584: Return Inside Finally Block";
pub const CWE_585: &'static str = "CWE-585: Empty Synchronized Block";
pub const CWE_586: &'static str = "CWE-586: Explicit Call to Finalize()";
pub const CWE_587: &'static str = "CWE-587: Assignment of a Fixed Address to a Pointer";
pub const CWE_588: &'static str = "CWE-588: Attempt to Access Child of a Non-structure Pointer";
pub const CWE_589: &'static str = "CWE-589: Call to Non-ubiquitous API";
pub const CWE_590: &'static str = "CWE-590: Free of Memory not on the Heap";
pub const CWE_591: &'static str = "CWE-591: Sensitive Data Storage in Improperly Locked Memory";
pub const CWE_593: &'static str =
    "CWE-593: Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created";
pub const CWE_594: &'static str = "CWE-594: J2EE Framework: Saving Unserializable Objects to Disk";
pub const CWE_595: &'static str =
    "CWE-595: Comparison of Object References Instead of Object Contents";
pub const CWE_597: &'static str = "CWE-597: Use of Wrong Operator in String Comparison";
pub const CWE_598: &'static str = "CWE-598: Use of GET Request Method With Sensitive Query Strings";
pub const CWE_599: &'static str = "CWE-599: Missing Validation of OpenSSL Certificate";
pub const CWE_600: &'static str = "CWE-600: Uncaught Exception in Servlet ";
pub const CWE_601: &'static str = "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')";
pub const CWE_602: &'static str = "CWE-602: Client-Side Enforcement of Server-Side Security";
pub const CWE_603: &'static str = "CWE-603: Use of Client-Side Authentication";
pub const CWE_605: &'static str = "CWE-605: Multiple Binds to the Same Port";
pub const CWE_606: &'static str = "CWE-606: Unchecked Input for Loop Condition";
pub const CWE_607: &'static str = "CWE-607: Public Static Final Field References Mutable Object";
pub const CWE_608: &'static str = "CWE-608: Struts: Non-private Field in ActionForm Class";
pub const CWE_609: &'static str = "CWE-609: Double-Checked Locking";
pub const CWE_610: &'static str =
    "CWE-610: Externally Controlled Reference to a Resource in Another Sphere";
pub const CWE_611: &'static str = "CWE-611: Improper Restriction of XML External Entity Reference";
pub const CWE_612: &'static str =
    "CWE-612: Improper Authorization of Index Containing Sensitive Information";
pub const CWE_613: &'static str = "CWE-613: Insufficient Session Expiration";
pub const CWE_614: &'static str =
    "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute";
pub const CWE_615: &'static str =
    "CWE-615: Inclusion of Sensitive Information in Source Code Comments";
pub const CWE_616: &'static str =
    "CWE-616: Incomplete Identification of Uploaded File Variables (PHP)";
pub const CWE_617: &'static str = "CWE-617: Reachable Assertion";
pub const CWE_618: &'static str = "CWE-618: Exposed Unsafe ActiveX Method";
pub const CWE_619: &'static str = "CWE-619: Dangling Database Cursor ('Cursor Injection')";
pub const CWE_620: &'static str = "CWE-620: Unverified Password Change";
pub const CWE_621: &'static str = "CWE-621: Variable Extraction Error";
pub const CWE_622: &'static str = "CWE-622: Improper Validation of Function Hook Arguments";
pub const CWE_623: &'static str = "CWE-623: Unsafe ActiveX Control Marked Safe For Scripting";
pub const CWE_624: &'static str = "CWE-624: Executable Regular Expression Error";
pub const CWE_625: &'static str = "CWE-625: Permissive Regular Expression";
pub const CWE_626: &'static str = "CWE-626: Null Byte Interaction Error (Poison Null Byte)";
pub const CWE_627: &'static str = "CWE-627: Dynamic Variable Evaluation";
pub const CWE_628: &'static str = "CWE-628: Function Call with Incorrectly Specified Arguments";
pub const CWE_636: &'static str = "CWE-636: Not Failing Securely ('Failing Open')";
pub const CWE_637: &'static str =
    "CWE-637: Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism')";
pub const CWE_638: &'static str = "CWE-638: Not Using Complete Mediation";
pub const CWE_639: &'static str = "CWE-639: Authorization Bypass Through User-Controlled Key";
pub const CWE_640: &'static str =
    "CWE-640: Weak Password Recovery Mechanism for Forgotten Password";
pub const CWE_641: &'static str =
    "CWE-641: Improper Restriction of Names for Files and Other Resources";
pub const CWE_642: &'static str = "CWE-642: External Control of Critical State Data";
pub const CWE_643: &'static str =
    "CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')";
pub const CWE_644: &'static str =
    "CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax";
pub const CWE_645: &'static str = "CWE-645: Overly Restrictive Account Lockout Mechanism";
pub const CWE_646: &'static str =
    "CWE-646: Reliance on File Name or Extension of Externally-Supplied File";
pub const CWE_647: &'static str =
    "CWE-647: Use of Non-Canonical URL Paths for Authorization Decisions";
pub const CWE_648: &'static str = "CWE-648: Incorrect Use of Privileged APIs";
pub const CWE_649: &'static str = "CWE-649: Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking";
pub const CWE_650: &'static str = "CWE-650: Trusting HTTP Permission Methods on the Server Side";
pub const CWE_651: &'static str = "CWE-651: Exposure of WSDL File Containing Sensitive Information";
pub const CWE_652: &'static str =
    "CWE-652: Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')";
pub const CWE_653: &'static str = "CWE-653: Improper Isolation or Compartmentalization";
pub const CWE_654: &'static str = "CWE-654: Reliance on a Single Factor in a Security Decision";
pub const CWE_655: &'static str = "CWE-655: Insufficient Psychological Acceptability";
pub const CWE_656: &'static str = "CWE-656: Reliance on Security Through Obscurity";
pub const CWE_657: &'static str = "CWE-657: Violation of Secure Design Principles";
pub const CWE_662: &'static str = "CWE-662: Improper Synchronization";
pub const CWE_663: &'static str =
    "CWE-663: Use of a Non-reentrant Function in a Concurrent Context";
pub const CWE_664: &'static str = "CWE-664: Improper Control of a Resource Through its Lifetime";
pub const CWE_665: &'static str = "CWE-665: Improper Initialization";
pub const CWE_666: &'static str = "CWE-666: Operation on Resource in Wrong Phase of Lifetime";
pub const CWE_667: &'static str = "CWE-667: Improper Locking";
pub const CWE_668: &'static str = "CWE-668: Exposure of Resource to Wrong Sphere";
pub const CWE_669: &'static str = "CWE-669: Incorrect Resource Transfer Between Spheres";
pub const CWE_670: &'static str = "CWE-670: Always-Incorrect Control Flow Implementation";
pub const CWE_671: &'static str = "CWE-671: Lack of Administrator Control over Security";
pub const CWE_672: &'static str = "CWE-672: Operation on a Resource after Expiration or Release";
pub const CWE_673: &'static str = "CWE-673: External Influence of Sphere Definition";
pub const CWE_674: &'static str = "CWE-674: Uncontrolled Recursion";
pub const CWE_675: &'static str =
    "CWE-675: Multiple Operations on Resource in Single-Operation Context";
pub const CWE_676: &'static str = "CWE-676: Use of Potentially Dangerous Function";
pub const CWE_680: &'static str = "CWE-680: Integer Overflow to Buffer Overflow";
pub const CWE_681: &'static str = "CWE-681: Incorrect Conversion between Numeric Types";
pub const CWE_682: &'static str = "CWE-682: Incorrect Calculation";
pub const CWE_683: &'static str = "CWE-683: Function Call With Incorrect Order of Arguments";
pub const CWE_684: &'static str = "CWE-684: Incorrect Provision of Specified Functionality";
pub const CWE_685: &'static str = "CWE-685: Function Call With Incorrect Number of Arguments";
pub const CWE_686: &'static str = "CWE-686: Function Call With Incorrect Argument Type";
pub const CWE_687: &'static str =
    "CWE-687: Function Call With Incorrectly Specified Argument Value";
pub const CWE_688: &'static str =
    "CWE-688: Function Call With Incorrect Variable or Reference as Argument";
pub const CWE_689: &'static str = "CWE-689: Permission Race Condition During Resource Copy";
pub const CWE_690: &'static str = "CWE-690: Unchecked Return Value to NULL Pointer Dereference";
pub const CWE_691: &'static str = "CWE-691: Insufficient Control Flow Management";
pub const CWE_692: &'static str = "CWE-692: Incomplete Denylist to Cross-Site Scripting";
pub const CWE_693: &'static str = "CWE-693: Protection Mechanism Failure";
pub const CWE_694: &'static str = "CWE-694: Use of Multiple Resources with Duplicate Identifier";
pub const CWE_695: &'static str = "CWE-695: Use of Low-Level Functionality";
pub const CWE_696: &'static str = "CWE-696: Incorrect Behavior Order";
pub const CWE_697: &'static str = "CWE-697: Incorrect Comparison";
pub const CWE_698: &'static str = "CWE-698: Execution After Redirect (EAR)";
pub const CWE_703: &'static str = "CWE-703: Improper Check or Handling of Exceptional Conditions";
pub const CWE_704: &'static str = "CWE-704: Incorrect Type Conversion or Cast";
pub const CWE_705: &'static str = "CWE-705: Incorrect Control Flow Scoping";
pub const CWE_706: &'static str = "CWE-706: Use of Incorrectly-Resolved Name or Reference";
pub const CWE_707: &'static str = "CWE-707: Improper Neutralization";
pub const CWE_708: &'static str = "CWE-708: Incorrect Ownership Assignment";
pub const CWE_710: &'static str = "CWE-710: Improper Adherence to Coding Standards";
pub const CWE_732: &'static str = "CWE-732: Incorrect Permission Assignment for Critical Resource";
pub const CWE_733: &'static str =
    "CWE-733: Compiler Optimization Removal or Modification of Security-critical Code";
pub const CWE_749: &'static str = "CWE-749: Exposed Dangerous Method or Function";
pub const CWE_754: &'static str = "CWE-754: Improper Check for Unusual or Exceptional Conditions";
pub const CWE_755: &'static str = "CWE-755: Improper Handling of Exceptional Conditions";
pub const CWE_756: &'static str = "CWE-756: Missing Custom Error Page";
pub const CWE_757: &'static str =
    "CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')";
pub const CWE_758: &'static str =
    "CWE-758: Reliance on Undefined, Unspecified, or Implementation-Defined Behavior";
pub const CWE_759: &'static str = "CWE-759: Use of a One-Way Hash without a Salt";
pub const CWE_760: &'static str = "CWE-760: Use of a One-Way Hash with a Predictable Salt";
pub const CWE_761: &'static str = "CWE-761: Free of Pointer not at Start of Buffer";
pub const CWE_762: &'static str = "CWE-762: Mismatched Memory Management Routines";
pub const CWE_763: &'static str = "CWE-763: Release of Invalid Pointer or Reference";
pub const CWE_764: &'static str = "CWE-764: Multiple Locks of a Critical Resource";
pub const CWE_765: &'static str = "CWE-765: Multiple Unlocks of a Critical Resource";
pub const CWE_766: &'static str = "CWE-766: Critical Data Element Declared Public";
pub const CWE_767: &'static str = "CWE-767: Access to Critical Private Variable via Public Method";
pub const CWE_768: &'static str = "CWE-768: Incorrect Short Circuit Evaluation";
pub const CWE_770: &'static str = "CWE-770: Allocation of Resources Without Limits or Throttling";
pub const CWE_771: &'static str = "CWE-771: Missing Reference to Active Allocated Resource";
pub const CWE_772: &'static str = "CWE-772: Missing Release of Resource after Effective Lifetime";
pub const CWE_773: &'static str = "CWE-773: Missing Reference to Active File Descriptor or Handle";
pub const CWE_774: &'static str =
    "CWE-774: Allocation of File Descriptors or Handles Without Limits or Throttling";
pub const CWE_775: &'static str =
    "CWE-775: Missing Release of File Descriptor or Handle after Effective Lifetime";
pub const CWE_776: &'static str =
    "CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')";
pub const CWE_777: &'static str = "CWE-777: Regular Expression without Anchors";
pub const CWE_778: &'static str = "CWE-778: Insufficient Logging";
pub const CWE_779: &'static str = "CWE-779: Logging of Excessive Data";
pub const CWE_780: &'static str = "CWE-780: Use of RSA Algorithm without OAEP";
pub const CWE_781: &'static str =
    "CWE-781: Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code";
pub const CWE_782: &'static str = "CWE-782: Exposed IOCTL with Insufficient Access Control";
pub const CWE_783: &'static str = "CWE-783: Operator Precedence Logic Error";
pub const CWE_784: &'static str =
    "CWE-784: Reliance on Cookies without Validation and Integrity Checking in a Security Decision";
pub const CWE_785: &'static str =
    "CWE-785: Use of Path Manipulation Function without Maximum-sized Buffer";
pub const CWE_786: &'static str = "CWE-786: Access of Memory Location Before Start of Buffer";
pub const CWE_787: &'static str = "CWE-787: Out-of-bounds Write";
pub const CWE_788: &'static str = "CWE-788: Access of Memory Location After End of Buffer";
pub const CWE_789: &'static str = "CWE-789: Memory Allocation with Excessive Size Value";
pub const CWE_790: &'static str = "CWE-790: Improper Filtering of Special Elements";
pub const CWE_791: &'static str = "CWE-791: Incomplete Filtering of Special Elements";
pub const CWE_792: &'static str =
    "CWE-792: Incomplete Filtering of One or More Instances of Special Elements";
pub const CWE_793: &'static str = "CWE-793: Only Filtering One Instance of a Special Element";
pub const CWE_794: &'static str =
    "CWE-794: Incomplete Filtering of Multiple Instances of Special Elements";
pub const CWE_795: &'static str =
    "CWE-795: Only Filtering Special Elements at a Specified Location";
pub const CWE_796: &'static str = "CWE-796: Only Filtering Special Elements Relative to a Marker";
pub const CWE_797: &'static str =
    "CWE-797: Only Filtering Special Elements at an Absolute Position";
pub const CWE_798: &'static str = "CWE-798: Use of Hard-coded Credentials";
pub const CWE_799: &'static str = "CWE-799: Improper Control of Interaction Frequency";
pub const CWE_804: &'static str = "CWE-804: Guessable CAPTCHA";
pub const CWE_805: &'static str = "CWE-805: Buffer Access with Incorrect Length Value";
pub const CWE_806: &'static str = "CWE-806: Buffer Access Using Size of Source Buffer";
pub const CWE_807: &'static str = "CWE-807: Reliance on Untrusted Inputs in a Security Decision";
pub const CWE_820: &'static str = "CWE-820: Missing Synchronization";
pub const CWE_821: &'static str = "CWE-821: Incorrect Synchronization";
pub const CWE_822: &'static str = "CWE-822: Untrusted Pointer Dereference";
pub const CWE_823: &'static str = "CWE-823: Use of Out-of-range Pointer Offset";
pub const CWE_824: &'static str = "CWE-824: Access of Uninitialized Pointer";
pub const CWE_825: &'static str = "CWE-825: Expired Pointer Dereference";
pub const CWE_826: &'static str = "CWE-826: Premature Release of Resource During Expected Lifetime";
pub const CWE_827: &'static str = "CWE-827: Improper Control of Document Type Definition";
pub const CWE_828: &'static str =
    "CWE-828: Signal Handler with Functionality that is not Asynchronous-Safe";
pub const CWE_829: &'static str =
    "CWE-829: Inclusion of Functionality from Untrusted Control Sphere";
pub const CWE_830: &'static str =
    "CWE-830: Inclusion of Web Functionality from an Untrusted Source";
pub const CWE_831: &'static str =
    "CWE-831: Signal Handler Function Associated with Multiple Signals";
pub const CWE_832: &'static str = "CWE-832: Unlock of a Resource that is not Locked";
pub const CWE_833: &'static str = "CWE-833: Deadlock";
pub const CWE_834: &'static str = "CWE-834: Excessive Iteration";
pub const CWE_835: &'static str = "CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')";
pub const CWE_836: &'static str =
    "CWE-836: Use of Password Hash Instead of Password for Authentication";
pub const CWE_837: &'static str = "CWE-837: Improper Enforcement of a Single, Unique Action";
pub const CWE_838: &'static str = "CWE-838: Inappropriate Encoding for Output Context";
pub const CWE_839: &'static str = "CWE-839: Numeric Range Comparison Without Minimum Check";
pub const CWE_841: &'static str = "CWE-841: Improper Enforcement of Behavioral Workflow";
pub const CWE_842: &'static str = "CWE-842: Placement of User into Incorrect Group";
pub const CWE_843: &'static str =
    "CWE-843: Access of Resource Using Incompatible Type ('Type Confusion')";
pub const CWE_862: &'static str = "CWE-862: Missing Authorization";
pub const CWE_863: &'static str = "CWE-863: Incorrect Authorization";
pub const CWE_908: &'static str = "CWE-908: Use of Uninitialized Resource";
pub const CWE_909: &'static str = "CWE-909: Missing Initialization of Resource";
pub const CWE_910: &'static str = "CWE-910: Use of Expired File Descriptor";
pub const CWE_911: &'static str = "CWE-911: Improper Update of Reference Count";
pub const CWE_912: &'static str = "CWE-912: Hidden Functionality";
pub const CWE_913: &'static str = "CWE-913: Improper Control of Dynamically-Managed Code Resources";
pub const CWE_914: &'static str = "CWE-914: Improper Control of Dynamically-Identified Variables";
pub const CWE_915: &'static str =
    "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes";
pub const CWE_916: &'static str =
    "CWE-916: Use of Password Hash With Insufficient Computational Effort";
pub const CWE_917: &'static str = "CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')";
pub const CWE_918: &'static str = "CWE-918: Server-Side Request Forgery (SSRF)";
pub const CWE_920: &'static str = "CWE-920: Improper Restriction of Power Consumption";
pub const CWE_921: &'static str =
    "CWE-921: Storage of Sensitive Data in a Mechanism without Access Control";
pub const CWE_922: &'static str = "CWE-922: Insecure Storage of Sensitive Information";
pub const CWE_923: &'static str =
    "CWE-923: Improper Restriction of Communication Channel to Intended Endpoints";
pub const CWE_924: &'static str = "CWE-924: Improper Enforcement of Message Integrity During Transmission in a Communication Channel";
pub const CWE_925: &'static str = "CWE-925: Improper Verification of Intent by Broadcast Receiver";
pub const CWE_926: &'static str = "CWE-926: Improper Export of Android Application Components";
pub const CWE_927: &'static str = "CWE-927: Use of Implicit Intent for Sensitive Communication";
pub const CWE_939: &'static str =
    "CWE-939: Improper Authorization in Handler for Custom URL Scheme";
pub const CWE_940: &'static str =
    "CWE-940: Improper Verification of Source of a Communication Channel";
pub const CWE_941: &'static str =
    "CWE-941: Incorrectly Specified Destination in a Communication Channel";
pub const CWE_942: &'static str = "CWE-942: Permissive Cross-domain Policy with Untrusted Domains";
pub const CWE_943: &'static str =
    "CWE-943: Improper Neutralization of Special Elements in Data Query Logic";
pub const CWE_1004: &'static str = "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag";
pub const CWE_1007: &'static str =
    "CWE-1007: Insufficient Visual Distinction of Homoglyphs Presented to User";
pub const CWE_1021: &'static str = "CWE-1021: Improper Restriction of Rendered UI Layers or Frames";
pub const CWE_1022: &'static str =
    "CWE-1022: Use of Web Link to Untrusted Target with window.opener Access";
pub const CWE_1023: &'static str = "CWE-1023: Incomplete Comparison with Missing Factors";
pub const CWE_1024: &'static str = "CWE-1024: Comparison of Incompatible Types";
pub const CWE_1025: &'static str = "CWE-1025: Comparison Using Wrong Factors";
pub const CWE_1037: &'static str =
    "CWE-1037: Processor Optimization Removal or Modification of Security-critical Code";
pub const CWE_1038: &'static str = "CWE-1038: Insecure Automated Optimizations";
pub const CWE_1039: &'static str = "CWE-1039: Automated Recognition Mechanism with Inadequate Detection or Handling of Adversarial Input Perturbations";
pub const CWE_1041: &'static str = "CWE-1041: Use of Redundant Code";
pub const CWE_1042: &'static str =
    "CWE-1042: Static Member Data Element outside of a Singleton Class Element";
pub const CWE_1043: &'static str =
    "CWE-1043: Data Element Aggregating an Excessively Large Number of Non-Primitive Elements";
pub const CWE_1044: &'static str =
    "CWE-1044: Architecture with Number of Horizontal Layers Outside of Expected Range";
pub const CWE_1045: &'static str = "CWE-1045: Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor";
pub const CWE_1046: &'static str =
    "CWE-1046: Creation of Immutable Text Using String Concatenation";
pub const CWE_1047: &'static str = "CWE-1047: Modules with Circular Dependencies";
pub const CWE_1048: &'static str =
    "CWE-1048: Invokable Control Element with Large Number of Outward Calls";
pub const CWE_1049: &'static str =
    "CWE-1049: Excessive Data Query Operations in a Large Data Table";
pub const CWE_1050: &'static str =
    "CWE-1050: Excessive Platform Resource Consumption within a Loop";
pub const CWE_1051: &'static str =
    "CWE-1051: Initialization with Hard-Coded Network Resource Configuration Data";
pub const CWE_1052: &'static str =
    "CWE-1052: Excessive Use of Hard-Coded Literals in Initialization";
pub const CWE_1053: &'static str = "CWE-1053: Missing Documentation for Design";
pub const CWE_1054: &'static str =
    "CWE-1054: Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer";
pub const CWE_1055: &'static str = "CWE-1055: Multiple Inheritance from Concrete Classes";
pub const CWE_1056: &'static str = "CWE-1056: Invokable Control Element with Variadic Parameters";
pub const CWE_1057: &'static str =
    "CWE-1057: Data Access Operations Outside of Expected Data Manager Component";
pub const CWE_1058: &'static str = "CWE-1058: Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element";
pub const CWE_1059: &'static str = "CWE-1059: Insufficient Technical Documentation";
pub const CWE_1060: &'static str =
    "CWE-1060: Excessive Number of Inefficient Server-Side Data Accesses";
pub const CWE_1061: &'static str = "CWE-1061: Insufficient Encapsulation";
pub const CWE_1062: &'static str = "CWE-1062: Parent Class with References to Child Class";
pub const CWE_1063: &'static str =
    "CWE-1063: Creation of Class Instance within a Static Code Block";
pub const CWE_1064: &'static str = "CWE-1064: Invokable Control Element with Signature Containing an Excessive Number of Parameters";
pub const CWE_1065: &'static str = "CWE-1065: Runtime Resource Management Control Element in a Component Built to Run on Application Servers";
pub const CWE_1066: &'static str = "CWE-1066: Missing Serialization Control Element";
pub const CWE_1067: &'static str =
    "CWE-1067: Excessive Execution of Sequential Searches of Data Resource";
pub const CWE_1068: &'static str =
    "CWE-1068: Inconsistency Between Implementation and Documented Design";
pub const CWE_1069: &'static str = "CWE-1069: Empty Exception Block";
pub const CWE_1070: &'static str =
    "CWE-1070: Serializable Data Element Containing non-Serializable Item Elements";
pub const CWE_1071: &'static str = "CWE-1071: Empty Code Block";
pub const CWE_1072: &'static str =
    "CWE-1072: Data Resource Access without Use of Connection Pooling";
pub const CWE_1073: &'static str =
    "CWE-1073: Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses";
pub const CWE_1074: &'static str = "CWE-1074: Class with Excessively Deep Inheritance";
pub const CWE_1075: &'static str =
    "CWE-1075: Unconditional Control Flow Transfer outside of Switch Block";
pub const CWE_1076: &'static str = "CWE-1076: Insufficient Adherence to Expected Conventions";
pub const CWE_1077: &'static str = "CWE-1077: Floating Point Comparison with Incorrect Operator";
pub const CWE_1078: &'static str = "CWE-1078: Inappropriate Source Code Style or Formatting";
pub const CWE_1079: &'static str = "CWE-1079: Parent Class without Virtual Destructor Method";
pub const CWE_1080: &'static str =
    "CWE-1080: Source Code File with Excessive Number of Lines of Code";
pub const CWE_1082: &'static str = "CWE-1082: Class Instance Self Destruction Control Element";
pub const CWE_1083: &'static str =
    "CWE-1083: Data Access from Outside Expected Data Manager Component";
pub const CWE_1084: &'static str =
    "CWE-1084: Invokable Control Element with Excessive File or Data Access Operations";
pub const CWE_1085: &'static str =
    "CWE-1085: Invokable Control Element with Excessive Volume of Commented-out Code";
pub const CWE_1086: &'static str = "CWE-1086: Class with Excessive Number of Child Classes";
pub const CWE_1087: &'static str =
    "CWE-1087: Class with Virtual Method without a Virtual Destructor";
pub const CWE_1088: &'static str =
    "CWE-1088: Synchronous Access of Remote Resource without Timeout";
pub const CWE_1089: &'static str = "CWE-1089: Large Data Table with Excessive Number of Indices";
pub const CWE_1090: &'static str =
    "CWE-1090: Method Containing Access of a Member Element from Another Class";
pub const CWE_1091: &'static str = "CWE-1091: Use of Object without Invoking Destructor Method";
pub const CWE_1092: &'static str =
    "CWE-1092: Use of Same Invokable Control Element in Multiple Architectural Layers";
pub const CWE_1093: &'static str = "CWE-1093: Excessively Complex Data Representation";
pub const CWE_1094: &'static str = "CWE-1094: Excessive Index Range Scan for a Data Resource";
pub const CWE_1095: &'static str = "CWE-1095: Loop Condition Value Update within the Loop";
pub const CWE_1096: &'static str =
    "CWE-1096: Singleton Class Instance Creation without Proper Locking or Synchronization";
pub const CWE_1097: &'static str =
    "CWE-1097: Persistent Storable Data Element without Associated Comparison Control Element";
pub const CWE_1098: &'static str =
    "CWE-1098: Data Element containing Pointer Item without Proper Copy Control Element";
pub const CWE_1099: &'static str = "CWE-1099: Inconsistent Naming Conventions for Identifiers";
pub const CWE_1100: &'static str = "CWE-1100: Insufficient Isolation of System-Dependent Functions";
pub const CWE_1101: &'static str = "CWE-1101: Reliance on Runtime Component in Generated Code";
pub const CWE_1102: &'static str = "CWE-1102: Reliance on Machine-Dependent Data Representation";
pub const CWE_1103: &'static str = "CWE-1103: Use of Platform-Dependent Third Party Components";
pub const CWE_1104: &'static str = "CWE-1104: Use of Unmaintained Third Party Components";
pub const CWE_1105: &'static str =
    "CWE-1105: Insufficient Encapsulation of Machine-Dependent Functionality";
pub const CWE_1106: &'static str = "CWE-1106: Insufficient Use of Symbolic pub constants";
pub const CWE_1107: &'static str =
    "CWE-1107: Insufficient Isolation of Symbolic pub constant Definitions";
pub const CWE_1108: &'static str = "CWE-1108: Excessive Reliance on Global Variables";
pub const CWE_1109: &'static str = "CWE-1109: Use of Same Variable for Multiple Purposes";
pub const CWE_1110: &'static str = "CWE-1110: Incomplete Design Documentation";
pub const CWE_1111: &'static str = "CWE-1111: Incomplete I/O Documentation";
pub const CWE_1112: &'static str = "CWE-1112: Incomplete Documentation of Program Execution";
pub const CWE_1113: &'static str = "CWE-1113: Inappropriate Comment Style";
pub const CWE_1114: &'static str = "CWE-1114: Inappropriate Whitespace Style";
pub const CWE_1115: &'static str = "CWE-1115: Source Code Element without Standard Prologue";
pub const CWE_1116: &'static str = "CWE-1116: Inaccurate Comments";
pub const CWE_1117: &'static str = "CWE-1117: Callable with Insufficient Behavioral Summary";
pub const CWE_1118: &'static str =
    "CWE-1118: Insufficient Documentation of Error Handling Techniques";
pub const CWE_1119: &'static str = "CWE-1119: Excessive Use of Unconditional Branching";
pub const CWE_1120: &'static str = "CWE-1120: Excessive Code Complexity";
pub const CWE_1121: &'static str = "CWE-1121: Excessive McCabe Cyclomatic Complexity";
pub const CWE_1122: &'static str = "CWE-1122: Excessive Halstead Complexity";
pub const CWE_1123: &'static str = "CWE-1123: Excessive Use of Self-Modifying Code";
pub const CWE_1124: &'static str = "CWE-1124: Excessively Deep Nesting";
pub const CWE_1125: &'static str = "CWE-1125: Excessive Attack Surface";
pub const CWE_1126: &'static str =
    "CWE-1126: Declaration of Variable with Unnecessarily Wide Scope";
pub const CWE_1127: &'static str = "CWE-1127: Compilation with Insufficient Warnings or Errors";
pub const CWE_1164: &'static str = "CWE-1164: Irrelevant Code";
pub const CWE_1173: &'static str = "CWE-1173: Improper Use of Validation Framework";
pub const CWE_1174: &'static str = "CWE-1174: ASP.NET Misconfiguration: Improper Model Validation";
pub const CWE_1176: &'static str = "CWE-1176: Inefficient CPU Computation";
pub const CWE_1177: &'static str = "CWE-1177: Use of Prohibited Code";
pub const CWE_1188: &'static str =
    "CWE-1188: Initialization of a Resource with an Insecure Default";
pub const CWE_1189: &'static str =
    "CWE-1189: Improper Isolation of Shared Resources on System-on-a-Chip (SoC)";
pub const CWE_1190: &'static str = "CWE-1190: DMA Device Enabled Too Early in Boot Phase";
pub const CWE_1191: &'static str =
    "CWE-1191: On-Chip Debug and Test Interface With Improper Access Control";
pub const CWE_1192: &'static str =
    "CWE-1192: System-on-Chip (SoC) Using Components without Unique, Immutable Identifiers";
pub const CWE_1193: &'static str =
    "CWE-1193: Power-On of Untrusted Execution Core Before Enabling Fabric Access Control";
pub const CWE_1204: &'static str = "CWE-1204: Generation of Weak Initialization Vector (IV)";
pub const CWE_1209: &'static str = "CWE-1209: Failure to Disable Reserved Bits";
pub const CWE_1220: &'static str = "CWE-1220: Insufficient Granularity of Access Control";
pub const CWE_1221: &'static str = "CWE-1221: Incorrect Register Defaults or Module Parameters";
pub const CWE_1222: &'static str =
    "CWE-1222: Insufficient Granularity of Address Regions Protected by Register Locks";
pub const CWE_1223: &'static str = "CWE-1223: Race Condition for Write-Once Attributes";
pub const CWE_1224: &'static str = "CWE-1224: Improper Restriction of Write-Once Bit Fields";
pub const CWE_1229: &'static str = "CWE-1229: Creation of Emergent Resource";
pub const CWE_1230: &'static str = "CWE-1230: Exposure of Sensitive Information Through Metadata";
pub const CWE_1231: &'static str = "CWE-1231: Improper Prevention of Lock Bit Modification";
pub const CWE_1232: &'static str = "CWE-1232: Improper Lock Behavior After Power State Transition";
pub const CWE_1233: &'static str =
    "CWE-1233: Security-Sensitive Hardware Controls with Missing Lock Bit Protection";
pub const CWE_1234: &'static str =
    "CWE-1234: Hardware Internal or Debug Modes Allow Override of Locks";
pub const CWE_1235: &'static str =
    "CWE-1235: Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations";
pub const CWE_1236: &'static str =
    "CWE-1236: Improper Neutralization of Formula Elements in a CSV File";
pub const CWE_1239: &'static str = "CWE-1239: Improper Zeroization of Hardware Register";
pub const CWE_1240: &'static str =
    "CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation";
pub const CWE_1241: &'static str =
    "CWE-1241: Use of Predictable Algorithm in Random Number Generator";
pub const CWE_1242: &'static str = "CWE-1242: Inclusion of Undocumented Features or Chicken Bits";
pub const CWE_1243: &'static str =
    "CWE-1243: Sensitive Non-Volatile Information Not Protected During Debug";
pub const CWE_1244: &'static str =
    "CWE-1244: Internal Asset Exposed to Unsafe Debug Access Level or State";
pub const CWE_1245: &'static str =
    "CWE-1245: Improper Finite State Machines (FSMs) in Hardware Logic";
pub const CWE_1246: &'static str =
    "CWE-1246: Improper Write Handling in Limited-write Non-Volatile Memories";
pub const CWE_1247: &'static str =
    "CWE-1247: Improper Protection Against Voltage and Clock Glitches";
pub const CWE_1248: &'static str =
    "CWE-1248: Semiconductor Defects in Hardware Logic with Security-Sensitive Implications";
pub const CWE_1249: &'static str =
    "CWE-1249: Application-Level Admin Tool with Inconsistent View of Underlying Operating System";
pub const CWE_1250: &'static str = "CWE-1250: Improper Preservation of Consistency Between Independent Representations of Shared State";
pub const CWE_1251: &'static str = "CWE-1251: Mirrored Regions with Different Values";
pub const CWE_1252: &'static str =
    "CWE-1252: CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations";
pub const CWE_1253: &'static str = "CWE-1253: Incorrect Selection of Fuse Values";
pub const CWE_1254: &'static str = "CWE-1254: Incorrect Comparison Logic Granularity";
pub const CWE_1255: &'static str =
    "CWE-1255: Comparison Logic is Vulnerable to Power Side-Channel Attacks";
pub const CWE_1256: &'static str =
    "CWE-1256: Improper Restriction of Software Interfaces to Hardware Features";
pub const CWE_1257: &'static str =
    "CWE-1257: Improper Access Control Applied to Mirrored or Aliased Memory Regions";
pub const CWE_1258: &'static str =
    "CWE-1258: Exposure of Sensitive System Information Due to Uncleared Debug Information";
pub const CWE_1259: &'static str = "CWE-1259: Improper Restriction of Security Token Assignment";
pub const CWE_1260: &'static str =
    "CWE-1260: Improper Handling of Overlap Between Protected Memory Ranges";
pub const CWE_1261: &'static str = "CWE-1261: Improper Handling of Single Event Upsets";
pub const CWE_1262: &'static str = "CWE-1262: Improper Access Control for Register Interface";
pub const CWE_1263: &'static str = "CWE-1263: Improper Physical Access Control";
pub const CWE_1264: &'static str =
    "CWE-1264: Hardware Logic with Insecure De-Synchronization between Control and Data Channels";
pub const CWE_1265: &'static str =
    "CWE-1265: Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls";
pub const CWE_1266: &'static str =
    "CWE-1266: Improper Scrubbing of Sensitive Data from Decommissioned Device";
pub const CWE_1267: &'static str = "CWE-1267: Policy Uses Obsolete Encoding";
pub const CWE_1268: &'static str =
    "CWE-1268: Policy Privileges are not Assigned Consistently Between Control and Data Agents";
pub const CWE_1269: &'static str = "CWE-1269: Product Released in Non-Release Configuration";
pub const CWE_1270: &'static str = "CWE-1270: Generation of Incorrect Security Tokens";
pub const CWE_1271: &'static str =
    "CWE-1271: Uninitialized Value on Reset for Registers Holding Security Settings";
pub const CWE_1272: &'static str =
    "CWE-1272: Sensitive Information Uncleared Before Debug/Power State Transition";
pub const CWE_1273: &'static str = "CWE-1273: Device Unlock Credential Sharing";
pub const CWE_1274: &'static str =
    "CWE-1274: Improper Access Control for Volatile Memory Containing Boot Code";
pub const CWE_1275: &'static str = "CWE-1275: Sensitive Cookie with Improper SameSite Attribute";
pub const CWE_1276: &'static str =
    "CWE-1276: Hardware Child Block Incorrectly Connected to Parent System";
pub const CWE_1277: &'static str = "CWE-1277: Firmware Not Updateable";
pub const CWE_1278: &'static str = "CWE-1278: Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques";
pub const CWE_1279: &'static str =
    "CWE-1279: Cryptographic Operations are run Before Supporting Units are Ready";
pub const CWE_1280: &'static str =
    "CWE-1280: Access Control Check Implemented After Asset is Accessed";
pub const CWE_1281: &'static str =
    "CWE-1281: Sequence of Processor Instructions Leads to Unexpected Behavior";
pub const CWE_1282: &'static str = "CWE-1282: Assumed-Immutable Data is Stored in Writable Memory";
pub const CWE_1283: &'static str = "CWE-1283: Mutable Attestation or Measurement Reporting Data";
pub const CWE_1284: &'static str = "CWE-1284: Improper Validation of Specified Quantity in Input";
pub const CWE_1285: &'static str =
    "CWE-1285: Improper Validation of Specified Index, Position, or Offset in Input";
pub const CWE_1286: &'static str =
    "CWE-1286: Improper Validation of Syntactic Correctness of Input";
pub const CWE_1287: &'static str = "CWE-1287: Improper Validation of Specified Type of Input";
pub const CWE_1288: &'static str = "CWE-1288: Improper Validation of Consistency within Input";
pub const CWE_1289: &'static str = "CWE-1289: Improper Validation of Unsafe Equivalence in Input";
pub const CWE_1290: &'static str = "CWE-1290: Incorrect Decoding of Security Identifiers ";
pub const CWE_1291: &'static str =
    "CWE-1291: Public Key Re-Use for Signing both Debug and Production Code";
pub const CWE_1292: &'static str = "CWE-1292: Incorrect Conversion of Security Identifiers";
pub const CWE_1293: &'static str =
    "CWE-1293: Missing Source Correlation of Multiple Independent Data";
pub const CWE_1294: &'static str = "CWE-1294: Insecure Security Identifier Mechanism";
pub const CWE_1295: &'static str = "CWE-1295: Debug Messages Revealing Unnecessary Information";
pub const CWE_1296: &'static str =
    "CWE-1296: Incorrect Chaining or Granularity of Debug Components";
pub const CWE_1297: &'static str =
    "CWE-1297: Unprotected Confidential Information on Device is Accessible by OSAT Vendors";
pub const CWE_1298: &'static str = "CWE-1298: Hardware Logic Contains Race Conditions";
pub const CWE_1299: &'static str =
    "CWE-1299: Missing Protection Mechanism for Alternate Hardware Interface";
pub const CWE_1300: &'static str = "CWE-1300: Improper Protection of Physical Side Channels";
pub const CWE_1301: &'static str =
    "CWE-1301: Insufficient or Incomplete Data Removal within Hardware Component";
pub const CWE_1302: &'static str = "CWE-1302: Missing Security Identifier";
pub const CWE_1303: &'static str =
    "CWE-1303: Non-Transparent Sharing of Microarchitectural Resources";
pub const CWE_1304: &'static str = "CWE-1304: Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation";
pub const CWE_1310: &'static str = "CWE-1310: Missing Ability to Patch ROM Code";
pub const CWE_1311: &'static str =
    "CWE-1311: Improper Translation of Security Attributes by Fabric Bridge";
pub const CWE_1312: &'static str =
    "CWE-1312: Missing Protection for Mirrored Regions in On-Chip Fabric Firewall";
pub const CWE_1313: &'static str =
    "CWE-1313: Hardware Allows Activation of Test or Debug Logic at Runtime";
pub const CWE_1314: &'static str = "CWE-1314: Missing Write Protection for Parametric Data Values";
pub const CWE_1315: &'static str =
    "CWE-1315: Improper Setting of Bus Controlling Capability in Fabric End-point";
pub const CWE_1316: &'static str = "CWE-1316: Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges";
pub const CWE_1317: &'static str = "CWE-1317: Improper Access Control in Fabric Bridge";
pub const CWE_1318: &'static str =
    "CWE-1318: Missing Support for Security Features in On-chip Fabrics or Buses";
pub const CWE_1319: &'static str =
    "CWE-1319: Improper Protection against Electromagnetic Fault Injection (EM-FI)";
pub const CWE_1320: &'static str =
    "CWE-1320: Improper Protection for Outbound Error Messages and Alert Signals";
pub const CWE_1321: &'static str = "CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')";
pub const CWE_1322: &'static str =
    "CWE-1322: Use of Blocking Code in Single-threaded, Non-blocking Context";
pub const CWE_1323: &'static str = "CWE-1323: Improper Management of Sensitive Trace Data";
pub const CWE_1325: &'static str = "CWE-1325: Improperly Controlled Sequential Memory Allocation";
pub const CWE_1326: &'static str = "CWE-1326: Missing Immutable Root of Trust in Hardware";
pub const CWE_1327: &'static str = "CWE-1327: Binding to an Unrestricted IP Address";
pub const CWE_1328: &'static str = "CWE-1328: Security Version Number Mutable to Older Versions";
pub const CWE_1329: &'static str = "CWE-1329: Reliance on Component That is Not Updateable";
pub const CWE_1330: &'static str = "CWE-1330: Remanent Data Readable after Memory Erase";
pub const CWE_1331: &'static str =
    "CWE-1331: Improper Isolation of Shared Resources in Network On Chip (NoC)";
pub const CWE_1332: &'static str =
    "CWE-1332: Improper Handling of Faults that Lead to Instruction Skips";
pub const CWE_1333: &'static str = "CWE-1333: Inefficient Regular Expression Complexity";
pub const CWE_1334: &'static str =
    "CWE-1334: Unauthorized Error Injection Can Degrade Hardware Redundancy";
pub const CWE_1335: &'static str = "CWE-1335: Incorrect Bitwise Shift of Integer";
pub const CWE_1336: &'static str =
    "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine";
pub const CWE_1338: &'static str = "CWE-1338: Improper Protections Against Hardware Overheating";
pub const CWE_1339: &'static str = "CWE-1339: Insufficient Precision or Accuracy of a Real Number";
pub const CWE_1341: &'static str = "CWE-1341: Multiple Releases of Same Resource or Handle";
pub const CWE_1342: &'static str =
    "CWE-1342: Information Exposure through Microarchitectural State after Transient Execution";
pub const CWE_1351: &'static str =
    "CWE-1351: Improper Handling of Hardware Behavior in Exceptionally Cold Environments";
pub const CWE_1357: &'static str = "CWE-1357: Reliance on Insufficiently Trustworthy Component";
pub const CWE_1384: &'static str =
    "CWE-1384: Improper Handling of Physical or Environmental Conditions";
pub const CWE_1385: &'static str = "CWE-1385: Missing Origin Validation in WebSockets";
pub const CWE_1386: &'static str = "CWE-1386: Insecure Operation on Windows Junction / Mount Point";
pub const CWE_1389: &'static str = "CWE-1389: Incorrect Parsing of Numbers with Different Radices";
pub const CWE_1390: &'static str = "CWE-1390: Weak Authentication";
pub const CWE_1391: &'static str = "CWE-1391: Use of Weak Credentials";
pub const CWE_1392: &'static str = "CWE-1392: Use of Default Credentials";
pub const CWE_1393: &'static str = "CWE-1393: Use of Default Password";
pub const CWE_1394: &'static str = "CWE-1394: Use of Default Cryptographic Key";
pub const CWE_1395: &'static str = "CWE-1395: Dependency on Vulnerable Third-Party Component";
pub const CWE_1419: &'static str = "CWE-1419: Incorrect Initialization of Resource";

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum CWE {
    #[serde(rename = "CWE-5")]
    Cwe5,
    #[serde(rename = "CWE-6")]
    Cwe6,
    #[serde(rename = "CWE-7")]
    Cwe7,
    #[serde(rename = "CWE-8")]
    Cwe8,
    #[serde(rename = "CWE-9")]
    Cwe9,
    #[serde(rename = "CWE-11")]
    Cwe11,
    #[serde(rename = "CWE-12")]
    Cwe12,
    #[serde(rename = "CWE-13")]
    Cwe13,
    #[serde(rename = "CWE-14")]
    Cwe14,
    #[serde(rename = "CWE-15")]
    Cwe15,
    #[serde(rename = "CWE-20")]
    Cwe20,
    #[serde(rename = "CWE-22")]
    Cwe22,
    #[serde(rename = "CWE-23")]
    Cwe23,
    #[serde(rename = "CWE-24")]
    Cwe24,
    #[serde(rename = "CWE-25")]
    Cwe25,
    #[serde(rename = "CWE-26")]
    Cwe26,
    #[serde(rename = "CWE-27")]
    Cwe27,
    #[serde(rename = "CWE-28")]
    Cwe28,
    #[serde(rename = "CWE-29")]
    Cwe29,
    #[serde(rename = "CWE-30")]
    Cwe30,
    #[serde(rename = "CWE-31")]
    Cwe31,
    #[serde(rename = "CWE-32")]
    Cwe32,
    #[serde(rename = "CWE-33")]
    Cwe33,
    #[serde(rename = "CWE-34")]
    Cwe34,
    #[serde(rename = "CWE-35")]
    Cwe35,
    #[serde(rename = "CWE-36")]
    Cwe36,
    #[serde(rename = "CWE-37")]
    Cwe37,
    #[serde(rename = "CWE-38")]
    Cwe38,
    #[serde(rename = "CWE-39")]
    Cwe39,
    #[serde(rename = "CWE-40")]
    Cwe40,
    #[serde(rename = "CWE-41")]
    Cwe41,
    #[serde(rename = "CWE-42")]
    Cwe42,
    #[serde(rename = "CWE-43")]
    Cwe43,
    #[serde(rename = "CWE-44")]
    Cwe44,
    #[serde(rename = "CWE-45")]
    Cwe45,
    #[serde(rename = "CWE-46")]
    Cwe46,
    #[serde(rename = "CWE-47")]
    Cwe47,
    #[serde(rename = "CWE-48")]
    Cwe48,
    #[serde(rename = "CWE-49")]
    Cwe49,
    #[serde(rename = "CWE-50")]
    Cwe50,
    #[serde(rename = "CWE-51")]
    Cwe51,
    #[serde(rename = "CWE-52")]
    Cwe52,
    #[serde(rename = "CWE-53")]
    Cwe53,
    #[serde(rename = "CWE-54")]
    Cwe54,
    #[serde(rename = "CWE-55")]
    Cwe55,
    #[serde(rename = "CWE-56")]
    Cwe56,
    #[serde(rename = "CWE-57")]
    Cwe57,
    #[serde(rename = "CWE-58")]
    Cwe58,
    #[serde(rename = "CWE-59")]
    Cwe59,
    #[serde(rename = "CWE-61")]
    Cwe61,
    #[serde(rename = "CWE-62")]
    Cwe62,
    #[serde(rename = "CWE-64")]
    Cwe64,
    #[serde(rename = "CWE-65")]
    Cwe65,
    #[serde(rename = "CWE-66")]
    Cwe66,
    #[serde(rename = "CWE-67")]
    Cwe67,
    #[serde(rename = "CWE-69")]
    Cwe69,
    #[serde(rename = "CWE-72")]
    Cwe72,
    #[serde(rename = "CWE-73")]
    Cwe73,
    #[serde(rename = "CWE-74")]
    Cwe74,
    #[serde(rename = "CWE-75")]
    Cwe75,
    #[serde(rename = "CWE-76")]
    Cwe76,
    #[serde(rename = "CWE-77")]
    Cwe77,
    #[serde(rename = "CWE-78")]
    Cwe78,
    #[serde(rename = "CWE-79")]
    Cwe79,
    #[serde(rename = "CWE-80")]
    Cwe80,
    #[serde(rename = "CWE-81")]
    Cwe81,
    #[serde(rename = "CWE-82")]
    Cwe82,
    #[serde(rename = "CWE-83")]
    Cwe83,
    #[serde(rename = "CWE-84")]
    Cwe84,
    #[serde(rename = "CWE-85")]
    Cwe85,
    #[serde(rename = "CWE-86")]
    Cwe86,
    #[serde(rename = "CWE-87")]
    Cwe87,
    #[serde(rename = "CWE-88")]
    Cwe88,
    #[serde(rename = "CWE-89")]
    Cwe89,
    #[serde(rename = "CWE-90")]
    Cwe90,
    #[serde(rename = "CWE-91")]
    Cwe91,
    #[serde(rename = "CWE-93")]
    Cwe93,
    #[serde(rename = "CWE-94")]
    Cwe94,
    #[serde(rename = "CWE-95")]
    Cwe95,
    #[serde(rename = "CWE-96")]
    Cwe96,
    #[serde(rename = "CWE-97")]
    Cwe97,
    #[serde(rename = "CWE-98")]
    Cwe98,
    #[serde(rename = "CWE-99")]
    Cwe99,
    #[serde(rename = "CWE-102")]
    Cwe102,
    #[serde(rename = "CWE-103")]
    Cwe103,
    #[serde(rename = "CWE-104")]
    Cwe104,
    #[serde(rename = "CWE-105")]
    Cwe105,
    #[serde(rename = "CWE-106")]
    Cwe106,
    #[serde(rename = "CWE-107")]
    Cwe107,
    #[serde(rename = "CWE-108")]
    Cwe108,
    #[serde(rename = "CWE-109")]
    Cwe109,
    #[serde(rename = "CWE-110")]
    Cwe110,
    #[serde(rename = "CWE-111")]
    Cwe111,
    #[serde(rename = "CWE-112")]
    Cwe112,
    #[serde(rename = "CWE-113")]
    Cwe113,
    #[serde(rename = "CWE-114")]
    Cwe114,
    #[serde(rename = "CWE-115")]
    Cwe115,
    #[serde(rename = "CWE-116")]
    Cwe116,
    #[serde(rename = "CWE-117")]
    Cwe117,
    #[serde(rename = "CWE-118")]
    Cwe118,
    #[serde(rename = "CWE-119")]
    Cwe119,
    #[serde(rename = "CWE-120")]
    Cwe120,
    #[serde(rename = "CWE-121")]
    Cwe121,
    #[serde(rename = "CWE-122")]
    Cwe122,
    #[serde(rename = "CWE-123")]
    Cwe123,
    #[serde(rename = "CWE-124")]
    Cwe124,
    #[serde(rename = "CWE-125")]
    Cwe125,
    #[serde(rename = "CWE-126")]
    Cwe126,
    #[serde(rename = "CWE-127")]
    Cwe127,
    #[serde(rename = "CWE-128")]
    Cwe128,
    #[serde(rename = "CWE-129")]
    Cwe129,
    #[serde(rename = "CWE-130")]
    Cwe130,
    #[serde(rename = "CWE-131")]
    Cwe131,
    #[serde(rename = "CWE-134")]
    Cwe134,
    #[serde(rename = "CWE-135")]
    Cwe135,
    #[serde(rename = "CWE-138")]
    Cwe138,
    #[serde(rename = "CWE-140")]
    Cwe140,
    #[serde(rename = "CWE-141")]
    Cwe141,
    #[serde(rename = "CWE-142")]
    Cwe142,
    #[serde(rename = "CWE-143")]
    Cwe143,
    #[serde(rename = "CWE-144")]
    Cwe144,
    #[serde(rename = "CWE-145")]
    Cwe145,
    #[serde(rename = "CWE-146")]
    Cwe146,
    #[serde(rename = "CWE-147")]
    Cwe147,
    #[serde(rename = "CWE-148")]
    Cwe148,
    #[serde(rename = "CWE-149")]
    Cwe149,
    #[serde(rename = "CWE-150")]
    Cwe150,
    #[serde(rename = "CWE-151")]
    Cwe151,
    #[serde(rename = "CWE-152")]
    Cwe152,
    #[serde(rename = "CWE-153")]
    Cwe153,
    #[serde(rename = "CWE-154")]
    Cwe154,
    #[serde(rename = "CWE-155")]
    Cwe155,
    #[serde(rename = "CWE-156")]
    Cwe156,
    #[serde(rename = "CWE-157")]
    Cwe157,
    #[serde(rename = "CWE-158")]
    Cwe158,
    #[serde(rename = "CWE-159")]
    Cwe159,
    #[serde(rename = "CWE-160")]
    Cwe160,
    #[serde(rename = "CWE-161")]
    Cwe161,
    #[serde(rename = "CWE-162")]
    Cwe162,
    #[serde(rename = "CWE-163")]
    Cwe163,
    #[serde(rename = "CWE-164")]
    Cwe164,
    #[serde(rename = "CWE-165")]
    Cwe165,
    #[serde(rename = "CWE-166")]
    Cwe166,
    #[serde(rename = "CWE-167")]
    Cwe167,
    #[serde(rename = "CWE-168")]
    Cwe168,
    #[serde(rename = "CWE-170")]
    Cwe170,
    #[serde(rename = "CWE-172")]
    Cwe172,
    #[serde(rename = "CWE-173")]
    Cwe173,
    #[serde(rename = "CWE-174")]
    Cwe174,
    #[serde(rename = "CWE-175")]
    Cwe175,
    #[serde(rename = "CWE-176")]
    Cwe176,
    #[serde(rename = "CWE-177")]
    Cwe177,
    #[serde(rename = "CWE-178")]
    Cwe178,
    #[serde(rename = "CWE-179")]
    Cwe179,
    #[serde(rename = "CWE-180")]
    Cwe180,
    #[serde(rename = "CWE-181")]
    Cwe181,
    #[serde(rename = "CWE-182")]
    Cwe182,
    #[serde(rename = "CWE-183")]
    Cwe183,
    #[serde(rename = "CWE-184")]
    Cwe184,
    #[serde(rename = "CWE-185")]
    Cwe185,
    #[serde(rename = "CWE-186")]
    Cwe186,
    #[serde(rename = "CWE-187")]
    Cwe187,
    #[serde(rename = "CWE-188")]
    Cwe188,
    #[serde(rename = "CWE-190")]
    Cwe190,
    #[serde(rename = "CWE-191")]
    Cwe191,
    #[serde(rename = "CWE-192")]
    Cwe192,
    #[serde(rename = "CWE-193")]
    Cwe193,
    #[serde(rename = "CWE-194")]
    Cwe194,
    #[serde(rename = "CWE-195")]
    Cwe195,
    #[serde(rename = "CWE-196")]
    Cwe196,
    #[serde(rename = "CWE-197")]
    Cwe197,
    #[serde(rename = "CWE-198")]
    Cwe198,
    #[serde(rename = "CWE-200")]
    Cwe200,
    #[serde(rename = "CWE-201")]
    Cwe201,
    #[serde(rename = "CWE-202")]
    Cwe202,
    #[serde(rename = "CWE-203")]
    Cwe203,
    #[serde(rename = "CWE-204")]
    Cwe204,
    #[serde(rename = "CWE-205")]
    Cwe205,
    #[serde(rename = "CWE-206")]
    Cwe206,
    #[serde(rename = "CWE-207")]
    Cwe207,
    #[serde(rename = "CWE-208")]
    Cwe208,
    #[serde(rename = "CWE-209")]
    Cwe209,
    #[serde(rename = "CWE-210")]
    Cwe210,
    #[serde(rename = "CWE-211")]
    Cwe211,
    #[serde(rename = "CWE-212")]
    Cwe212,
    #[serde(rename = "CWE-213")]
    Cwe213,
    #[serde(rename = "CWE-214")]
    Cwe214,
    #[serde(rename = "CWE-215")]
    Cwe215,
    #[serde(rename = "CWE-219")]
    Cwe219,
    #[serde(rename = "CWE-220")]
    Cwe220,
    #[serde(rename = "CWE-221")]
    Cwe221,
    #[serde(rename = "CWE-222")]
    Cwe222,
    #[serde(rename = "CWE-223")]
    Cwe223,
    #[serde(rename = "CWE-224")]
    Cwe224,
    #[serde(rename = "CWE-226")]
    Cwe226,
    #[serde(rename = "CWE-228")]
    Cwe228,
    #[serde(rename = "CWE-229")]
    Cwe229,
    #[serde(rename = "CWE-230")]
    Cwe230,
    #[serde(rename = "CWE-231")]
    Cwe231,
    #[serde(rename = "CWE-232")]
    Cwe232,
    #[serde(rename = "CWE-233")]
    Cwe233,
    #[serde(rename = "CWE-234")]
    Cwe234,
    #[serde(rename = "CWE-235")]
    Cwe235,
    #[serde(rename = "CWE-236")]
    Cwe236,
    #[serde(rename = "CWE-237")]
    Cwe237,
    #[serde(rename = "CWE-238")]
    Cwe238,
    #[serde(rename = "CWE-239")]
    Cwe239,
    #[serde(rename = "CWE-240")]
    Cwe240,
    #[serde(rename = "CWE-241")]
    Cwe241,
    #[serde(rename = "CWE-242")]
    Cwe242,
    #[serde(rename = "CWE-243")]
    Cwe243,
    #[serde(rename = "CWE-244")]
    Cwe244,
    #[serde(rename = "CWE-245")]
    Cwe245,
    #[serde(rename = "CWE-246")]
    Cwe246,
    #[serde(rename = "CWE-248")]
    Cwe248,
    #[serde(rename = "CWE-250")]
    Cwe250,
    #[serde(rename = "CWE-252")]
    Cwe252,
    #[serde(rename = "CWE-253")]
    Cwe253,
    #[serde(rename = "CWE-256")]
    Cwe256,
    #[serde(rename = "CWE-257")]
    Cwe257,
    #[serde(rename = "CWE-258")]
    Cwe258,
    #[serde(rename = "CWE-259")]
    Cwe259,
    #[serde(rename = "CWE-260")]
    Cwe260,
    #[serde(rename = "CWE-261")]
    Cwe261,
    #[serde(rename = "CWE-262")]
    Cwe262,
    #[serde(rename = "CWE-263")]
    Cwe263,
    #[serde(rename = "CWE-266")]
    Cwe266,
    #[serde(rename = "CWE-267")]
    Cwe267,
    #[serde(rename = "CWE-268")]
    Cwe268,
    #[serde(rename = "CWE-269")]
    Cwe269,
    #[serde(rename = "CWE-270")]
    Cwe270,
    #[serde(rename = "CWE-271")]
    Cwe271,
    #[serde(rename = "CWE-272")]
    Cwe272,
    #[serde(rename = "CWE-273")]
    Cwe273,
    #[serde(rename = "CWE-274")]
    Cwe274,
    #[serde(rename = "CWE-276")]
    Cwe276,
    #[serde(rename = "CWE-277")]
    Cwe277,
    #[serde(rename = "CWE-278")]
    Cwe278,
    #[serde(rename = "CWE-279")]
    Cwe279,
    #[serde(rename = "CWE-280")]
    Cwe280,
    #[serde(rename = "CWE-281")]
    Cwe281,
    #[serde(rename = "CWE-282")]
    Cwe282,
    #[serde(rename = "CWE-283")]
    Cwe283,
    #[serde(rename = "CWE-284")]
    Cwe284,
    #[serde(rename = "CWE-285")]
    Cwe285,
    #[serde(rename = "CWE-286")]
    Cwe286,
    #[serde(rename = "CWE-287")]
    Cwe287,
    #[serde(rename = "CWE-288")]
    Cwe288,
    #[serde(rename = "CWE-289")]
    Cwe289,
    #[serde(rename = "CWE-290")]
    Cwe290,
    #[serde(rename = "CWE-291")]
    Cwe291,
    #[serde(rename = "CWE-293")]
    Cwe293,
    #[serde(rename = "CWE-294")]
    Cwe294,
    #[serde(rename = "CWE-295")]
    Cwe295,
    #[serde(rename = "CWE-296")]
    Cwe296,
    #[serde(rename = "CWE-297")]
    Cwe297,
    #[serde(rename = "CWE-298")]
    Cwe298,
    #[serde(rename = "CWE-299")]
    Cwe299,
    #[serde(rename = "CWE-300")]
    Cwe300,
    #[serde(rename = "CWE-301")]
    Cwe301,
    #[serde(rename = "CWE-302")]
    Cwe302,
    #[serde(rename = "CWE-303")]
    Cwe303,
    #[serde(rename = "CWE-304")]
    Cwe304,
    #[serde(rename = "CWE-305")]
    Cwe305,
    #[serde(rename = "CWE-306")]
    Cwe306,
    #[serde(rename = "CWE-307")]
    Cwe307,
    #[serde(rename = "CWE-308")]
    Cwe308,
    #[serde(rename = "CWE-309")]
    Cwe309,
    #[serde(rename = "CWE-311")]
    Cwe311,
    #[serde(rename = "CWE-312")]
    Cwe312,
    #[serde(rename = "CWE-313")]
    Cwe313,
    #[serde(rename = "CWE-314")]
    Cwe314,
    #[serde(rename = "CWE-315")]
    Cwe315,
    #[serde(rename = "CWE-316")]
    Cwe316,
    #[serde(rename = "CWE-317")]
    Cwe317,
    #[serde(rename = "CWE-318")]
    Cwe318,
    #[serde(rename = "CWE-319")]
    Cwe319,
    #[serde(rename = "CWE-321")]
    Cwe321,
    #[serde(rename = "CWE-322")]
    Cwe322,
    #[serde(rename = "CWE-323")]
    Cwe323,
    #[serde(rename = "CWE-324")]
    Cwe324,
    #[serde(rename = "CWE-325")]
    Cwe325,
    #[serde(rename = "CWE-326")]
    Cwe326,
    #[serde(rename = "CWE-327")]
    Cwe327,
    #[serde(rename = "CWE-328")]
    Cwe328,
    #[serde(rename = "CWE-329")]
    Cwe329,
    #[serde(rename = "CWE-330")]
    Cwe330,
    #[serde(rename = "CWE-331")]
    Cwe331,
    #[serde(rename = "CWE-332")]
    Cwe332,
    #[serde(rename = "CWE-333")]
    Cwe333,
    #[serde(rename = "CWE-334")]
    Cwe334,
    #[serde(rename = "CWE-335")]
    Cwe335,
    #[serde(rename = "CWE-336")]
    Cwe336,
    #[serde(rename = "CWE-337")]
    Cwe337,
    #[serde(rename = "CWE-338")]
    Cwe338,
    #[serde(rename = "CWE-339")]
    Cwe339,
    #[serde(rename = "CWE-340")]
    Cwe340,
    #[serde(rename = "CWE-341")]
    Cwe341,
    #[serde(rename = "CWE-342")]
    Cwe342,
    #[serde(rename = "CWE-343")]
    Cwe343,
    #[serde(rename = "CWE-344")]
    Cwe344,
    #[serde(rename = "CWE-345")]
    Cwe345,
    #[serde(rename = "CWE-346")]
    Cwe346,
    #[serde(rename = "CWE-347")]
    Cwe347,
    #[serde(rename = "CWE-348")]
    Cwe348,
    #[serde(rename = "CWE-349")]
    Cwe349,
    #[serde(rename = "CWE-350")]
    Cwe350,
    #[serde(rename = "CWE-351")]
    Cwe351,
    #[serde(rename = "CWE-352")]
    Cwe352,
    #[serde(rename = "CWE-353")]
    Cwe353,
    #[serde(rename = "CWE-354")]
    Cwe354,
    #[serde(rename = "CWE-356")]
    Cwe356,
    #[serde(rename = "CWE-357")]
    Cwe357,
    #[serde(rename = "CWE-358")]
    Cwe358,
    #[serde(rename = "CWE-359")]
    Cwe359,
    #[serde(rename = "CWE-360")]
    Cwe360,
    #[serde(rename = "CWE-362")]
    Cwe362,
    #[serde(rename = "CWE-363")]
    Cwe363,
    #[serde(rename = "CWE-364")]
    Cwe364,
    #[serde(rename = "CWE-366")]
    Cwe366,
    #[serde(rename = "CWE-367")]
    Cwe367,
    #[serde(rename = "CWE-368")]
    Cwe368,
    #[serde(rename = "CWE-369")]
    Cwe369,
    #[serde(rename = "CWE-370")]
    Cwe370,
    #[serde(rename = "CWE-372")]
    Cwe372,
    #[serde(rename = "CWE-374")]
    Cwe374,
    #[serde(rename = "CWE-375")]
    Cwe375,
    #[serde(rename = "CWE-377")]
    Cwe377,
    #[serde(rename = "CWE-378")]
    Cwe378,
    #[serde(rename = "CWE-379")]
    Cwe379,
    #[serde(rename = "CWE-382")]
    Cwe382,
    #[serde(rename = "CWE-383")]
    Cwe383,
    #[serde(rename = "CWE-384")]
    Cwe384,
    #[serde(rename = "CWE-385")]
    Cwe385,
    #[serde(rename = "CWE-386")]
    Cwe386,
    #[serde(rename = "CWE-390")]
    Cwe390,
    #[serde(rename = "CWE-391")]
    Cwe391,
    #[serde(rename = "CWE-392")]
    Cwe392,
    #[serde(rename = "CWE-393")]
    Cwe393,
    #[serde(rename = "CWE-394")]
    Cwe394,
    #[serde(rename = "CWE-395")]
    Cwe395,
    #[serde(rename = "CWE-396")]
    Cwe396,
    #[serde(rename = "CWE-397")]
    Cwe397,
    #[serde(rename = "CWE-400")]
    Cwe400,
    #[serde(rename = "CWE-401")]
    Cwe401,
    #[serde(rename = "CWE-402")]
    Cwe402,
    #[serde(rename = "CWE-403")]
    Cwe403,
    #[serde(rename = "CWE-404")]
    Cwe404,
    #[serde(rename = "CWE-405")]
    Cwe405,
    #[serde(rename = "CWE-406")]
    Cwe406,
    #[serde(rename = "CWE-407")]
    Cwe407,
    #[serde(rename = "CWE-408")]
    Cwe408,
    #[serde(rename = "CWE-409")]
    Cwe409,
    #[serde(rename = "CWE-410")]
    Cwe410,
    #[serde(rename = "CWE-412")]
    Cwe412,
    #[serde(rename = "CWE-413")]
    Cwe413,
    #[serde(rename = "CWE-414")]
    Cwe414,
    #[serde(rename = "CWE-415")]
    Cwe415,
    #[serde(rename = "CWE-416")]
    Cwe416,
    #[serde(rename = "CWE-419")]
    Cwe419,
    #[serde(rename = "CWE-420")]
    Cwe420,
    #[serde(rename = "CWE-421")]
    Cwe421,
    #[serde(rename = "CWE-422")]
    Cwe422,
    #[serde(rename = "CWE-424")]
    Cwe424,
    #[serde(rename = "CWE-425")]
    Cwe425,
    #[serde(rename = "CWE-426")]
    Cwe426,
    #[serde(rename = "CWE-427")]
    Cwe427,
    #[serde(rename = "CWE-428")]
    Cwe428,
    #[serde(rename = "CWE-430")]
    Cwe430,
    #[serde(rename = "CWE-431")]
    Cwe431,
    #[serde(rename = "CWE-432")]
    Cwe432,
    #[serde(rename = "CWE-433")]
    Cwe433,
    #[serde(rename = "CWE-434")]
    Cwe434,
    #[serde(rename = "CWE-435")]
    Cwe435,
    #[serde(rename = "CWE-436")]
    Cwe436,
    #[serde(rename = "CWE-437")]
    Cwe437,
    #[serde(rename = "CWE-439")]
    Cwe439,
    #[serde(rename = "CWE-440")]
    Cwe440,
    #[serde(rename = "CWE-441")]
    Cwe441,
    #[serde(rename = "CWE-444")]
    Cwe444,
    #[serde(rename = "CWE-446")]
    Cwe446,
    #[serde(rename = "CWE-447")]
    Cwe447,
    #[serde(rename = "CWE-448")]
    Cwe448,
    #[serde(rename = "CWE-449")]
    Cwe449,
    #[serde(rename = "CWE-450")]
    Cwe450,
    #[serde(rename = "CWE-451")]
    Cwe451,
    #[serde(rename = "CWE-453")]
    Cwe453,
    #[serde(rename = "CWE-454")]
    Cwe454,
    #[serde(rename = "CWE-455")]
    Cwe455,
    #[serde(rename = "CWE-456")]
    Cwe456,
    #[serde(rename = "CWE-457")]
    Cwe457,
    #[serde(rename = "CWE-459")]
    Cwe459,
    #[serde(rename = "CWE-460")]
    Cwe460,
    #[serde(rename = "CWE-462")]
    Cwe462,
    #[serde(rename = "CWE-463")]
    Cwe463,
    #[serde(rename = "CWE-464")]
    Cwe464,
    #[serde(rename = "CWE-466")]
    Cwe466,
    #[serde(rename = "CWE-467")]
    Cwe467,
    #[serde(rename = "CWE-468")]
    Cwe468,
    #[serde(rename = "CWE-469")]
    Cwe469,
    #[serde(rename = "CWE-470")]
    Cwe470,
    #[serde(rename = "CWE-471")]
    Cwe471,
    #[serde(rename = "CWE-472")]
    Cwe472,
    #[serde(rename = "CWE-473")]
    Cwe473,
    #[serde(rename = "CWE-474")]
    Cwe474,
    #[serde(rename = "CWE-475")]
    Cwe475,
    #[serde(rename = "CWE-476")]
    Cwe476,
    #[serde(rename = "CWE-477")]
    Cwe477,
    #[serde(rename = "CWE-478")]
    Cwe478,
    #[serde(rename = "CWE-479")]
    Cwe479,
    #[serde(rename = "CWE-480")]
    Cwe480,
    #[serde(rename = "CWE-481")]
    Cwe481,
    #[serde(rename = "CWE-482")]
    Cwe482,
    #[serde(rename = "CWE-483")]
    Cwe483,
    #[serde(rename = "CWE-484")]
    Cwe484,
    #[serde(rename = "CWE-486")]
    Cwe486,
    #[serde(rename = "CWE-487")]
    Cwe487,
    #[serde(rename = "CWE-488")]
    Cwe488,
    #[serde(rename = "CWE-489")]
    Cwe489,
    #[serde(rename = "CWE-491")]
    Cwe491,
    #[serde(rename = "CWE-492")]
    Cwe492,
    #[serde(rename = "CWE-493")]
    Cwe493,
    #[serde(rename = "CWE-494")]
    Cwe494,
    #[serde(rename = "CWE-495")]
    Cwe495,
    #[serde(rename = "CWE-496")]
    Cwe496,
    #[serde(rename = "CWE-497")]
    Cwe497,
    #[serde(rename = "CWE-498")]
    Cwe498,
    #[serde(rename = "CWE-499")]
    Cwe499,
    #[serde(rename = "CWE-500")]
    Cwe500,
    #[serde(rename = "CWE-501")]
    Cwe501,
    #[serde(rename = "CWE-502")]
    Cwe502,
    #[serde(rename = "CWE-506")]
    Cwe506,
    #[serde(rename = "CWE-507")]
    Cwe507,
    #[serde(rename = "CWE-508")]
    Cwe508,
    #[serde(rename = "CWE-509")]
    Cwe509,
    #[serde(rename = "CWE-510")]
    Cwe510,
    #[serde(rename = "CWE-511")]
    Cwe511,
    #[serde(rename = "CWE-512")]
    Cwe512,
    #[serde(rename = "CWE-514")]
    Cwe514,
    #[serde(rename = "CWE-515")]
    Cwe515,
    #[serde(rename = "CWE-520")]
    Cwe520,
    #[serde(rename = "CWE-521")]
    Cwe521,
    #[serde(rename = "CWE-522")]
    Cwe522,
    #[serde(rename = "CWE-523")]
    Cwe523,
    #[serde(rename = "CWE-524")]
    Cwe524,
    #[serde(rename = "CWE-525")]
    Cwe525,
    #[serde(rename = "CWE-526")]
    Cwe526,
    #[serde(rename = "CWE-527")]
    Cwe527,
    #[serde(rename = "CWE-528")]
    Cwe528,
    #[serde(rename = "CWE-529")]
    Cwe529,
    #[serde(rename = "CWE-530")]
    Cwe530,
    #[serde(rename = "CWE-531")]
    Cwe531,
    #[serde(rename = "CWE-532")]
    Cwe532,
    #[serde(rename = "CWE-535")]
    Cwe535,
    #[serde(rename = "CWE-536")]
    Cwe536,
    #[serde(rename = "CWE-537")]
    Cwe537,
    #[serde(rename = "CWE-538")]
    Cwe538,
    #[serde(rename = "CWE-539")]
    Cwe539,
    #[serde(rename = "CWE-540")]
    Cwe540,
    #[serde(rename = "CWE-541")]
    Cwe541,
    #[serde(rename = "CWE-543")]
    Cwe543,
    #[serde(rename = "CWE-544")]
    Cwe544,
    #[serde(rename = "CWE-546")]
    Cwe546,
    #[serde(rename = "CWE-547")]
    Cwe547,
    #[serde(rename = "CWE-548")]
    Cwe548,
    #[serde(rename = "CWE-549")]
    Cwe549,
    #[serde(rename = "CWE-550")]
    Cwe550,
    #[serde(rename = "CWE-551")]
    Cwe551,
    #[serde(rename = "CWE-552")]
    Cwe552,
    #[serde(rename = "CWE-553")]
    Cwe553,
    #[serde(rename = "CWE-554")]
    Cwe554,
    #[serde(rename = "CWE-555")]
    Cwe555,
    #[serde(rename = "CWE-556")]
    Cwe556,
    #[serde(rename = "CWE-558")]
    Cwe558,
    #[serde(rename = "CWE-560")]
    Cwe560,
    #[serde(rename = "CWE-561")]
    Cwe561,
    #[serde(rename = "CWE-562")]
    Cwe562,
    #[serde(rename = "CWE-563")]
    Cwe563,
    #[serde(rename = "CWE-564")]
    Cwe564,
    #[serde(rename = "CWE-565")]
    Cwe565,
    #[serde(rename = "CWE-566")]
    Cwe566,
    #[serde(rename = "CWE-567")]
    Cwe567,
    #[serde(rename = "CWE-568")]
    Cwe568,
    #[serde(rename = "CWE-570")]
    Cwe570,
    #[serde(rename = "CWE-571")]
    Cwe571,
    #[serde(rename = "CWE-572")]
    Cwe572,
    #[serde(rename = "CWE-573")]
    Cwe573,
    #[serde(rename = "CWE-574")]
    Cwe574,
    #[serde(rename = "CWE-575")]
    Cwe575,
    #[serde(rename = "CWE-576")]
    Cwe576,
    #[serde(rename = "CWE-577")]
    Cwe577,
    #[serde(rename = "CWE-578")]
    Cwe578,
    #[serde(rename = "CWE-579")]
    Cwe579,
    #[serde(rename = "CWE-580")]
    Cwe580,
    #[serde(rename = "CWE-581")]
    Cwe581,
    #[serde(rename = "CWE-582")]
    Cwe582,
    #[serde(rename = "CWE-583")]
    Cwe583,
    #[serde(rename = "CWE-584")]
    Cwe584,
    #[serde(rename = "CWE-585")]
    Cwe585,
    #[serde(rename = "CWE-586")]
    Cwe586,
    #[serde(rename = "CWE-587")]
    Cwe587,
    #[serde(rename = "CWE-588")]
    Cwe588,
    #[serde(rename = "CWE-589")]
    Cwe589,
    #[serde(rename = "CWE-590")]
    Cwe590,
    #[serde(rename = "CWE-591")]
    Cwe591,
    #[serde(rename = "CWE-593")]
    Cwe593,
    #[serde(rename = "CWE-594")]
    Cwe594,
    #[serde(rename = "CWE-595")]
    Cwe595,
    #[serde(rename = "CWE-597")]
    Cwe597,
    #[serde(rename = "CWE-598")]
    Cwe598,
    #[serde(rename = "CWE-599")]
    Cwe599,
    #[serde(rename = "CWE-600")]
    Cwe600,
    #[serde(rename = "CWE-601")]
    Cwe601,
    #[serde(rename = "CWE-602")]
    Cwe602,
    #[serde(rename = "CWE-603")]
    Cwe603,
    #[serde(rename = "CWE-605")]
    Cwe605,
    #[serde(rename = "CWE-606")]
    Cwe606,
    #[serde(rename = "CWE-607")]
    Cwe607,
    #[serde(rename = "CWE-608")]
    Cwe608,
    #[serde(rename = "CWE-609")]
    Cwe609,
    #[serde(rename = "CWE-610")]
    Cwe610,
    #[serde(rename = "CWE-611")]
    Cwe611,
    #[serde(rename = "CWE-612")]
    Cwe612,
    #[serde(rename = "CWE-613")]
    Cwe613,
    #[serde(rename = "CWE-614")]
    Cwe614,
    #[serde(rename = "CWE-615")]
    Cwe615,
    #[serde(rename = "CWE-616")]
    Cwe616,
    #[serde(rename = "CWE-617")]
    Cwe617,
    #[serde(rename = "CWE-618")]
    Cwe618,
    #[serde(rename = "CWE-619")]
    Cwe619,
    #[serde(rename = "CWE-620")]
    Cwe620,
    #[serde(rename = "CWE-621")]
    Cwe621,
    #[serde(rename = "CWE-622")]
    Cwe622,
    #[serde(rename = "CWE-623")]
    Cwe623,
    #[serde(rename = "CWE-624")]
    Cwe624,
    #[serde(rename = "CWE-625")]
    Cwe625,
    #[serde(rename = "CWE-626")]
    Cwe626,
    #[serde(rename = "CWE-627")]
    Cwe627,
    #[serde(rename = "CWE-628")]
    Cwe628,
    #[serde(rename = "CWE-636")]
    Cwe636,
    #[serde(rename = "CWE-637")]
    Cwe637,
    #[serde(rename = "CWE-638")]
    Cwe638,
    #[serde(rename = "CWE-639")]
    Cwe639,
    #[serde(rename = "CWE-640")]
    Cwe640,
    #[serde(rename = "CWE-641")]
    Cwe641,
    #[serde(rename = "CWE-642")]
    Cwe642,
    #[serde(rename = "CWE-643")]
    Cwe643,
    #[serde(rename = "CWE-644")]
    Cwe644,
    #[serde(rename = "CWE-645")]
    Cwe645,
    #[serde(rename = "CWE-646")]
    Cwe646,
    #[serde(rename = "CWE-647")]
    Cwe647,
    #[serde(rename = "CWE-648")]
    Cwe648,
    #[serde(rename = "CWE-649")]
    Cwe649,
    #[serde(rename = "CWE-650")]
    Cwe650,
    #[serde(rename = "CWE-651")]
    Cwe651,
    #[serde(rename = "CWE-652")]
    Cwe652,
    #[serde(rename = "CWE-653")]
    Cwe653,
    #[serde(rename = "CWE-654")]
    Cwe654,
    #[serde(rename = "CWE-655")]
    Cwe655,
    #[serde(rename = "CWE-656")]
    Cwe656,
    #[serde(rename = "CWE-657")]
    Cwe657,
    #[serde(rename = "CWE-662")]
    Cwe662,
    #[serde(rename = "CWE-663")]
    Cwe663,
    #[serde(rename = "CWE-664")]
    Cwe664,
    #[serde(rename = "CWE-665")]
    Cwe665,
    #[serde(rename = "CWE-666")]
    Cwe666,
    #[serde(rename = "CWE-667")]
    Cwe667,
    #[serde(rename = "CWE-668")]
    Cwe668,
    #[serde(rename = "CWE-669")]
    Cwe669,
    #[serde(rename = "CWE-670")]
    Cwe670,
    #[serde(rename = "CWE-671")]
    Cwe671,
    #[serde(rename = "CWE-672")]
    Cwe672,
    #[serde(rename = "CWE-673")]
    Cwe673,
    #[serde(rename = "CWE-674")]
    Cwe674,
    #[serde(rename = "CWE-675")]
    Cwe675,
    #[serde(rename = "CWE-676")]
    Cwe676,
    #[serde(rename = "CWE-680")]
    Cwe680,
    #[serde(rename = "CWE-681")]
    Cwe681,
    #[serde(rename = "CWE-682")]
    Cwe682,
    #[serde(rename = "CWE-683")]
    Cwe683,
    #[serde(rename = "CWE-684")]
    Cwe684,
    #[serde(rename = "CWE-685")]
    Cwe685,
    #[serde(rename = "CWE-686")]
    Cwe686,
    #[serde(rename = "CWE-687")]
    Cwe687,
    #[serde(rename = "CWE-688")]
    Cwe688,
    #[serde(rename = "CWE-689")]
    Cwe689,
    #[serde(rename = "CWE-690")]
    Cwe690,
    #[serde(rename = "CWE-691")]
    Cwe691,
    #[serde(rename = "CWE-692")]
    Cwe692,
    #[serde(rename = "CWE-693")]
    Cwe693,
    #[serde(rename = "CWE-694")]
    Cwe694,
    #[serde(rename = "CWE-695")]
    Cwe695,
    #[serde(rename = "CWE-696")]
    Cwe696,
    #[serde(rename = "CWE-697")]
    Cwe697,
    #[serde(rename = "CWE-698")]
    Cwe698,
    #[serde(rename = "CWE-703")]
    Cwe703,
    #[serde(rename = "CWE-704")]
    Cwe704,
    #[serde(rename = "CWE-705")]
    Cwe705,
    #[serde(rename = "CWE-706")]
    Cwe706,
    #[serde(rename = "CWE-707")]
    Cwe707,
    #[serde(rename = "CWE-708")]
    Cwe708,
    #[serde(rename = "CWE-710")]
    Cwe710,
    #[serde(rename = "CWE-732")]
    Cwe732,
    #[serde(rename = "CWE-733")]
    Cwe733,
    #[serde(rename = "CWE-749")]
    Cwe749,
    #[serde(rename = "CWE-754")]
    Cwe754,
    #[serde(rename = "CWE-755")]
    Cwe755,
    #[serde(rename = "CWE-756")]
    Cwe756,
    #[serde(rename = "CWE-757")]
    Cwe757,
    #[serde(rename = "CWE-758")]
    Cwe758,
    #[serde(rename = "CWE-759")]
    Cwe759,
    #[serde(rename = "CWE-760")]
    Cwe760,
    #[serde(rename = "CWE-761")]
    Cwe761,
    #[serde(rename = "CWE-762")]
    Cwe762,
    #[serde(rename = "CWE-763")]
    Cwe763,
    #[serde(rename = "CWE-764")]
    Cwe764,
    #[serde(rename = "CWE-765")]
    Cwe765,
    #[serde(rename = "CWE-766")]
    Cwe766,
    #[serde(rename = "CWE-767")]
    Cwe767,
    #[serde(rename = "CWE-768")]
    Cwe768,
    #[serde(rename = "CWE-770")]
    Cwe770,
    #[serde(rename = "CWE-771")]
    Cwe771,
    #[serde(rename = "CWE-772")]
    Cwe772,
    #[serde(rename = "CWE-773")]
    Cwe773,
    #[serde(rename = "CWE-774")]
    Cwe774,
    #[serde(rename = "CWE-775")]
    Cwe775,
    #[serde(rename = "CWE-776")]
    Cwe776,
    #[serde(rename = "CWE-777")]
    Cwe777,
    #[serde(rename = "CWE-778")]
    Cwe778,
    #[serde(rename = "CWE-779")]
    Cwe779,
    #[serde(rename = "CWE-780")]
    Cwe780,
    #[serde(rename = "CWE-781")]
    Cwe781,
    #[serde(rename = "CWE-782")]
    Cwe782,
    #[serde(rename = "CWE-783")]
    Cwe783,
    #[serde(rename = "CWE-784")]
    Cwe784,
    #[serde(rename = "CWE-785")]
    Cwe785,
    #[serde(rename = "CWE-786")]
    Cwe786,
    #[serde(rename = "CWE-787")]
    Cwe787,
    #[serde(rename = "CWE-788")]
    Cwe788,
    #[serde(rename = "CWE-789")]
    Cwe789,
    #[serde(rename = "CWE-790")]
    Cwe790,
    #[serde(rename = "CWE-791")]
    Cwe791,
    #[serde(rename = "CWE-792")]
    Cwe792,
    #[serde(rename = "CWE-793")]
    Cwe793,
    #[serde(rename = "CWE-794")]
    Cwe794,
    #[serde(rename = "CWE-795")]
    Cwe795,
    #[serde(rename = "CWE-796")]
    Cwe796,
    #[serde(rename = "CWE-797")]
    Cwe797,
    #[serde(rename = "CWE-798")]
    Cwe798,
    #[serde(rename = "CWE-799")]
    Cwe799,
    #[serde(rename = "CWE-804")]
    Cwe804,
    #[serde(rename = "CWE-805")]
    Cwe805,
    #[serde(rename = "CWE-806")]
    Cwe806,
    #[serde(rename = "CWE-807")]
    Cwe807,
    #[serde(rename = "CWE-820")]
    Cwe820,
    #[serde(rename = "CWE-821")]
    Cwe821,
    #[serde(rename = "CWE-822")]
    Cwe822,
    #[serde(rename = "CWE-823")]
    Cwe823,
    #[serde(rename = "CWE-824")]
    Cwe824,
    #[serde(rename = "CWE-825")]
    Cwe825,
    #[serde(rename = "CWE-826")]
    Cwe826,
    #[serde(rename = "CWE-827")]
    Cwe827,
    #[serde(rename = "CWE-828")]
    Cwe828,
    #[serde(rename = "CWE-829")]
    Cwe829,
    #[serde(rename = "CWE-830")]
    Cwe830,
    #[serde(rename = "CWE-831")]
    Cwe831,
    #[serde(rename = "CWE-832")]
    Cwe832,
    #[serde(rename = "CWE-833")]
    Cwe833,
    #[serde(rename = "CWE-834")]
    Cwe834,
    #[serde(rename = "CWE-835")]
    Cwe835,
    #[serde(rename = "CWE-836")]
    Cwe836,
    #[serde(rename = "CWE-837")]
    Cwe837,
    #[serde(rename = "CWE-838")]
    Cwe838,
    #[serde(rename = "CWE-839")]
    Cwe839,
    #[serde(rename = "CWE-841")]
    Cwe841,
    #[serde(rename = "CWE-842")]
    Cwe842,
    #[serde(rename = "CWE-843")]
    Cwe843,
    #[serde(rename = "CWE-862")]
    Cwe862,
    #[serde(rename = "CWE-863")]
    Cwe863,
    #[serde(rename = "CWE-908")]
    Cwe908,
    #[serde(rename = "CWE-909")]
    Cwe909,
    #[serde(rename = "CWE-910")]
    Cwe910,
    #[serde(rename = "CWE-911")]
    Cwe911,
    #[serde(rename = "CWE-912")]
    Cwe912,
    #[serde(rename = "CWE-913")]
    Cwe913,
    #[serde(rename = "CWE-914")]
    Cwe914,
    #[serde(rename = "CWE-915")]
    Cwe915,
    #[serde(rename = "CWE-916")]
    Cwe916,
    #[serde(rename = "CWE-917")]
    Cwe917,
    #[serde(rename = "CWE-918")]
    Cwe918,
    #[serde(rename = "CWE-920")]
    Cwe920,
    #[serde(rename = "CWE-921")]
    Cwe921,
    #[serde(rename = "CWE-922")]
    Cwe922,
    #[serde(rename = "CWE-923")]
    Cwe923,
    #[serde(rename = "CWE-924")]
    Cwe924,
    #[serde(rename = "CWE-925")]
    Cwe925,
    #[serde(rename = "CWE-926")]
    Cwe926,
    #[serde(rename = "CWE-927")]
    Cwe927,
    #[serde(rename = "CWE-939")]
    Cwe939,
    #[serde(rename = "CWE-940")]
    Cwe940,
    #[serde(rename = "CWE-941")]
    Cwe941,
    #[serde(rename = "CWE-942")]
    Cwe942,
    #[serde(rename = "CWE-943")]
    Cwe943,
    #[serde(rename = "CWE-1004")]
    Cwe1004,
    #[serde(rename = "CWE-1007")]
    Cwe1007,
    #[serde(rename = "CWE-1021")]
    Cwe1021,
    #[serde(rename = "CWE-1022")]
    Cwe1022,
    #[serde(rename = "CWE-1023")]
    Cwe1023,
    #[serde(rename = "CWE-1024")]
    Cwe1024,
    #[serde(rename = "CWE-1025")]
    Cwe1025,
    #[serde(rename = "CWE-1037")]
    Cwe1037,
    #[serde(rename = "CWE-1038")]
    Cwe1038,
    #[serde(rename = "CWE-1039")]
    Cwe1039,
    #[serde(rename = "CWE-1041")]
    Cwe1041,
    #[serde(rename = "CWE-1042")]
    Cwe1042,
    #[serde(rename = "CWE-1043")]
    Cwe1043,
    #[serde(rename = "CWE-1044")]
    Cwe1044,
    #[serde(rename = "CWE-1045")]
    Cwe1045,
    #[serde(rename = "CWE-1046")]
    Cwe1046,
    #[serde(rename = "CWE-1047")]
    Cwe1047,
    #[serde(rename = "CWE-1048")]
    Cwe1048,
    #[serde(rename = "CWE-1049")]
    Cwe1049,
    #[serde(rename = "CWE-1050")]
    Cwe1050,
    #[serde(rename = "CWE-1051")]
    Cwe1051,
    #[serde(rename = "CWE-1052")]
    Cwe1052,
    #[serde(rename = "CWE-1053")]
    Cwe1053,
    #[serde(rename = "CWE-1054")]
    Cwe1054,
    #[serde(rename = "CWE-1055")]
    Cwe1055,
    #[serde(rename = "CWE-1056")]
    Cwe1056,
    #[serde(rename = "CWE-1057")]
    Cwe1057,
    #[serde(rename = "CWE-1058")]
    Cwe1058,
    #[serde(rename = "CWE-1059")]
    Cwe1059,
    #[serde(rename = "CWE-1060")]
    Cwe1060,
    #[serde(rename = "CWE-1061")]
    Cwe1061,
    #[serde(rename = "CWE-1062")]
    Cwe1062,
    #[serde(rename = "CWE-1063")]
    Cwe1063,
    #[serde(rename = "CWE-1064")]
    Cwe1064,
    #[serde(rename = "CWE-1065")]
    Cwe1065,
    #[serde(rename = "CWE-1066")]
    Cwe1066,
    #[serde(rename = "CWE-1067")]
    Cwe1067,
    #[serde(rename = "CWE-1068")]
    Cwe1068,
    #[serde(rename = "CWE-1069")]
    Cwe1069,
    #[serde(rename = "CWE-1070")]
    Cwe1070,
    #[serde(rename = "CWE-1071")]
    Cwe1071,
    #[serde(rename = "CWE-1072")]
    Cwe1072,
    #[serde(rename = "CWE-1073")]
    Cwe1073,
    #[serde(rename = "CWE-1074")]
    Cwe1074,
    #[serde(rename = "CWE-1075")]
    Cwe1075,
    #[serde(rename = "CWE-1076")]
    Cwe1076,
    #[serde(rename = "CWE-1077")]
    Cwe1077,
    #[serde(rename = "CWE-1078")]
    Cwe1078,
    #[serde(rename = "CWE-1079")]
    Cwe1079,
    #[serde(rename = "CWE-1080")]
    Cwe1080,
    #[serde(rename = "CWE-1082")]
    Cwe1082,
    #[serde(rename = "CWE-1083")]
    Cwe1083,
    #[serde(rename = "CWE-1084")]
    Cwe1084,
    #[serde(rename = "CWE-1085")]
    Cwe1085,
    #[serde(rename = "CWE-1086")]
    Cwe1086,
    #[serde(rename = "CWE-1087")]
    Cwe1087,
    #[serde(rename = "CWE-1088")]
    Cwe1088,
    #[serde(rename = "CWE-1089")]
    Cwe1089,
    #[serde(rename = "CWE-1090")]
    Cwe1090,
    #[serde(rename = "CWE-1091")]
    Cwe1091,
    #[serde(rename = "CWE-1092")]
    Cwe1092,
    #[serde(rename = "CWE-1093")]
    Cwe1093,
    #[serde(rename = "CWE-1094")]
    Cwe1094,
    #[serde(rename = "CWE-1095")]
    Cwe1095,
    #[serde(rename = "CWE-1096")]
    Cwe1096,
    #[serde(rename = "CWE-1097")]
    Cwe1097,
    #[serde(rename = "CWE-1098")]
    Cwe1098,
    #[serde(rename = "CWE-1099")]
    Cwe1099,
    #[serde(rename = "CWE-1100")]
    Cwe1100,
    #[serde(rename = "CWE-1101")]
    Cwe1101,
    #[serde(rename = "CWE-1102")]
    Cwe1102,
    #[serde(rename = "CWE-1103")]
    Cwe1103,
    #[serde(rename = "CWE-1104")]
    Cwe1104,
    #[serde(rename = "CWE-1105")]
    Cwe1105,
    #[serde(rename = "CWE-1106")]
    Cwe1106,
    #[serde(rename = "CWE-1107")]
    Cwe1107,
    #[serde(rename = "CWE-1108")]
    Cwe1108,
    #[serde(rename = "CWE-1109")]
    Cwe1109,
    #[serde(rename = "CWE-1110")]
    Cwe1110,
    #[serde(rename = "CWE-1111")]
    Cwe1111,
    #[serde(rename = "CWE-1112")]
    Cwe1112,
    #[serde(rename = "CWE-1113")]
    Cwe1113,
    #[serde(rename = "CWE-1114")]
    Cwe1114,
    #[serde(rename = "CWE-1115")]
    Cwe1115,
    #[serde(rename = "CWE-1116")]
    Cwe1116,
    #[serde(rename = "CWE-1117")]
    Cwe1117,
    #[serde(rename = "CWE-1118")]
    Cwe1118,
    #[serde(rename = "CWE-1119")]
    Cwe1119,
    #[serde(rename = "CWE-1120")]
    Cwe1120,
    #[serde(rename = "CWE-1121")]
    Cwe1121,
    #[serde(rename = "CWE-1122")]
    Cwe1122,
    #[serde(rename = "CWE-1123")]
    Cwe1123,
    #[serde(rename = "CWE-1124")]
    Cwe1124,
    #[serde(rename = "CWE-1125")]
    Cwe1125,
    #[serde(rename = "CWE-1126")]
    Cwe1126,
    #[serde(rename = "CWE-1127")]
    Cwe1127,
    #[serde(rename = "CWE-1164")]
    Cwe1164,
    #[serde(rename = "CWE-1173")]
    Cwe1173,
    #[serde(rename = "CWE-1174")]
    Cwe1174,
    #[serde(rename = "CWE-1176")]
    Cwe1176,
    #[serde(rename = "CWE-1177")]
    Cwe1177,
    #[serde(rename = "CWE-1188")]
    Cwe1188,
    #[serde(rename = "CWE-1189")]
    Cwe1189,
    #[serde(rename = "CWE-1190")]
    Cwe1190,
    #[serde(rename = "CWE-1191")]
    Cwe1191,
    #[serde(rename = "CWE-1192")]
    Cwe1192,
    #[serde(rename = "CWE-1193")]
    Cwe1193,
    #[serde(rename = "CWE-1204")]
    Cwe1204,
    #[serde(rename = "CWE-1209")]
    Cwe1209,
    #[serde(rename = "CWE-1220")]
    Cwe1220,
    #[serde(rename = "CWE-1221")]
    Cwe1221,
    #[serde(rename = "CWE-1222")]
    Cwe1222,
    #[serde(rename = "CWE-1223")]
    Cwe1223,
    #[serde(rename = "CWE-1224")]
    Cwe1224,
    #[serde(rename = "CWE-1229")]
    Cwe1229,
    #[serde(rename = "CWE-1230")]
    Cwe1230,
    #[serde(rename = "CWE-1231")]
    Cwe1231,
    #[serde(rename = "CWE-1232")]
    Cwe1232,
    #[serde(rename = "CWE-1233")]
    Cwe1233,
    #[serde(rename = "CWE-1234")]
    Cwe1234,
    #[serde(rename = "CWE-1235")]
    Cwe1235,
    #[serde(rename = "CWE-1236")]
    Cwe1236,
    #[serde(rename = "CWE-1239")]
    Cwe1239,
    #[serde(rename = "CWE-1240")]
    Cwe1240,
    #[serde(rename = "CWE-1241")]
    Cwe1241,
    #[serde(rename = "CWE-1242")]
    Cwe1242,
    #[serde(rename = "CWE-1243")]
    Cwe1243,
    #[serde(rename = "CWE-1244")]
    Cwe1244,
    #[serde(rename = "CWE-1245")]
    Cwe1245,
    #[serde(rename = "CWE-1246")]
    Cwe1246,
    #[serde(rename = "CWE-1247")]
    Cwe1247,
    #[serde(rename = "CWE-1248")]
    Cwe1248,
    #[serde(rename = "CWE-1249")]
    Cwe1249,
    #[serde(rename = "CWE-1250")]
    Cwe1250,
    #[serde(rename = "CWE-1251")]
    Cwe1251,
    #[serde(rename = "CWE-1252")]
    Cwe1252,
    #[serde(rename = "CWE-1253")]
    Cwe1253,
    #[serde(rename = "CWE-1254")]
    Cwe1254,
    #[serde(rename = "CWE-1255")]
    Cwe1255,
    #[serde(rename = "CWE-1256")]
    Cwe1256,
    #[serde(rename = "CWE-1257")]
    Cwe1257,
    #[serde(rename = "CWE-1258")]
    Cwe1258,
    #[serde(rename = "CWE-1259")]
    Cwe1259,
    #[serde(rename = "CWE-1260")]
    Cwe1260,
    #[serde(rename = "CWE-1261")]
    Cwe1261,
    #[serde(rename = "CWE-1262")]
    Cwe1262,
    #[serde(rename = "CWE-1263")]
    Cwe1263,
    #[serde(rename = "CWE-1264")]
    Cwe1264,
    #[serde(rename = "CWE-1265")]
    Cwe1265,
    #[serde(rename = "CWE-1266")]
    Cwe1266,
    #[serde(rename = "CWE-1267")]
    Cwe1267,
    #[serde(rename = "CWE-1268")]
    Cwe1268,
    #[serde(rename = "CWE-1269")]
    Cwe1269,
    #[serde(rename = "CWE-1270")]
    Cwe1270,
    #[serde(rename = "CWE-1271")]
    Cwe1271,
    #[serde(rename = "CWE-1272")]
    Cwe1272,
    #[serde(rename = "CWE-1273")]
    Cwe1273,
    #[serde(rename = "CWE-1274")]
    Cwe1274,
    #[serde(rename = "CWE-1275")]
    Cwe1275,
    #[serde(rename = "CWE-1276")]
    Cwe1276,
    #[serde(rename = "CWE-1277")]
    Cwe1277,
    #[serde(rename = "CWE-1278")]
    Cwe1278,
    #[serde(rename = "CWE-1279")]
    Cwe1279,
    #[serde(rename = "CWE-1280")]
    Cwe1280,
    #[serde(rename = "CWE-1281")]
    Cwe1281,
    #[serde(rename = "CWE-1282")]
    Cwe1282,
    #[serde(rename = "CWE-1283")]
    Cwe1283,
    #[serde(rename = "CWE-1284")]
    Cwe1284,
    #[serde(rename = "CWE-1285")]
    Cwe1285,
    #[serde(rename = "CWE-1286")]
    Cwe1286,
    #[serde(rename = "CWE-1287")]
    Cwe1287,
    #[serde(rename = "CWE-1288")]
    Cwe1288,
    #[serde(rename = "CWE-1289")]
    Cwe1289,
    #[serde(rename = "CWE-1290")]
    Cwe1290,
    #[serde(rename = "CWE-1291")]
    Cwe1291,
    #[serde(rename = "CWE-1292")]
    Cwe1292,
    #[serde(rename = "CWE-1293")]
    Cwe1293,
    #[serde(rename = "CWE-1294")]
    Cwe1294,
    #[serde(rename = "CWE-1295")]
    Cwe1295,
    #[serde(rename = "CWE-1296")]
    Cwe1296,
    #[serde(rename = "CWE-1297")]
    Cwe1297,
    #[serde(rename = "CWE-1298")]
    Cwe1298,
    #[serde(rename = "CWE-1299")]
    Cwe1299,
    #[serde(rename = "CWE-1300")]
    Cwe1300,
    #[serde(rename = "CWE-1301")]
    Cwe1301,
    #[serde(rename = "CWE-1302")]
    Cwe1302,
    #[serde(rename = "CWE-1303")]
    Cwe1303,
    #[serde(rename = "CWE-1304")]
    Cwe1304,
    #[serde(rename = "CWE-1310")]
    Cwe1310,
    #[serde(rename = "CWE-1311")]
    Cwe1311,
    #[serde(rename = "CWE-1312")]
    Cwe1312,
    #[serde(rename = "CWE-1313")]
    Cwe1313,
    #[serde(rename = "CWE-1314")]
    Cwe1314,
    #[serde(rename = "CWE-1315")]
    Cwe1315,
    #[serde(rename = "CWE-1316")]
    Cwe1316,
    #[serde(rename = "CWE-1317")]
    Cwe1317,
    #[serde(rename = "CWE-1318")]
    Cwe1318,
    #[serde(rename = "CWE-1319")]
    Cwe1319,
    #[serde(rename = "CWE-1320")]
    Cwe1320,
    #[serde(rename = "CWE-1321")]
    Cwe1321,
    #[serde(rename = "CWE-1322")]
    Cwe1322,
    #[serde(rename = "CWE-1323")]
    Cwe1323,
    #[serde(rename = "CWE-1325")]
    Cwe1325,
    #[serde(rename = "CWE-1326")]
    Cwe1326,
    #[serde(rename = "CWE-1327")]
    Cwe1327,
    #[serde(rename = "CWE-1328")]
    Cwe1328,
    #[serde(rename = "CWE-1329")]
    Cwe1329,
    #[serde(rename = "CWE-1330")]
    Cwe1330,
    #[serde(rename = "CWE-1331")]
    Cwe1331,
    #[serde(rename = "CWE-1332")]
    Cwe1332,
    #[serde(rename = "CWE-1333")]
    Cwe1333,
    #[serde(rename = "CWE-1334")]
    Cwe1334,
    #[serde(rename = "CWE-1335")]
    Cwe1335,
    #[serde(rename = "CWE-1336")]
    Cwe1336,
    #[serde(rename = "CWE-1338")]
    Cwe1338,
    #[serde(rename = "CWE-1339")]
    Cwe1339,
    #[serde(rename = "CWE-1341")]
    Cwe1341,
    #[serde(rename = "CWE-1342")]
    Cwe1342,
    #[serde(rename = "CWE-1351")]
    Cwe1351,
    #[serde(rename = "CWE-1357")]
    Cwe1357,
    #[serde(rename = "CWE-1384")]
    Cwe1384,
    #[serde(rename = "CWE-1385")]
    Cwe1385,
    #[serde(rename = "CWE-1386")]
    Cwe1386,
    #[serde(rename = "CWE-1389")]
    Cwe1389,
    #[serde(rename = "CWE-1390")]
    Cwe1390,
    #[serde(rename = "CWE-1391")]
    Cwe1391,
    #[serde(rename = "CWE-1392")]
    Cwe1392,
    #[serde(rename = "CWE-1393")]
    Cwe1393,
    #[serde(rename = "CWE-1394")]
    Cwe1394,
    #[serde(rename = "CWE-1395")]
    Cwe1395,
    #[serde(rename = "CWE-1419")]
    Cwe1419,
}

impl CWE {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cwe5 => CWE_5,
            Self::Cwe6 => CWE_6,
            Self::Cwe7 => CWE_7,
            Self::Cwe8 => CWE_8,
            Self::Cwe9 => CWE_9,
            Self::Cwe11 => CWE_11,
            Self::Cwe12 => CWE_12,
            Self::Cwe13 => CWE_13,
            Self::Cwe14 => CWE_14,
            Self::Cwe15 => CWE_15,
            Self::Cwe20 => CWE_20,
            Self::Cwe22 => CWE_22,
            Self::Cwe23 => CWE_23,
            Self::Cwe24 => CWE_24,
            Self::Cwe25 => CWE_25,
            Self::Cwe26 => CWE_26,
            Self::Cwe27 => CWE_27,
            Self::Cwe28 => CWE_28,
            Self::Cwe29 => CWE_29,
            Self::Cwe30 => CWE_30,
            Self::Cwe31 => CWE_31,
            Self::Cwe32 => CWE_32,
            Self::Cwe33 => CWE_33,
            Self::Cwe34 => CWE_34,
            Self::Cwe35 => CWE_35,
            Self::Cwe36 => CWE_36,
            Self::Cwe37 => CWE_37,
            Self::Cwe38 => CWE_38,
            Self::Cwe39 => CWE_39,
            Self::Cwe40 => CWE_40,
            Self::Cwe41 => CWE_41,
            Self::Cwe42 => CWE_42,
            Self::Cwe43 => CWE_43,
            Self::Cwe44 => CWE_44,
            Self::Cwe45 => CWE_45,
            Self::Cwe46 => CWE_46,
            Self::Cwe47 => CWE_47,
            Self::Cwe48 => CWE_48,
            Self::Cwe49 => CWE_49,
            Self::Cwe50 => CWE_50,
            Self::Cwe51 => CWE_51,
            Self::Cwe52 => CWE_52,
            Self::Cwe53 => CWE_53,
            Self::Cwe54 => CWE_54,
            Self::Cwe55 => CWE_55,
            Self::Cwe56 => CWE_56,
            Self::Cwe57 => CWE_57,
            Self::Cwe58 => CWE_58,
            Self::Cwe59 => CWE_59,
            Self::Cwe61 => CWE_61,
            Self::Cwe62 => CWE_62,
            Self::Cwe64 => CWE_64,
            Self::Cwe65 => CWE_65,
            Self::Cwe66 => CWE_66,
            Self::Cwe67 => CWE_67,
            Self::Cwe69 => CWE_69,
            Self::Cwe72 => CWE_72,
            Self::Cwe73 => CWE_73,
            Self::Cwe74 => CWE_74,
            Self::Cwe75 => CWE_75,
            Self::Cwe76 => CWE_76,
            Self::Cwe77 => CWE_77,
            Self::Cwe78 => CWE_78,
            Self::Cwe79 => CWE_79,
            Self::Cwe80 => CWE_80,
            Self::Cwe81 => CWE_81,
            Self::Cwe82 => CWE_82,
            Self::Cwe83 => CWE_83,
            Self::Cwe84 => CWE_84,
            Self::Cwe85 => CWE_85,
            Self::Cwe86 => CWE_86,
            Self::Cwe87 => CWE_87,
            Self::Cwe88 => CWE_88,
            Self::Cwe89 => CWE_89,
            Self::Cwe90 => CWE_90,
            Self::Cwe91 => CWE_91,
            Self::Cwe93 => CWE_93,
            Self::Cwe94 => CWE_94,
            Self::Cwe95 => CWE_95,
            Self::Cwe96 => CWE_96,
            Self::Cwe97 => CWE_97,
            Self::Cwe98 => CWE_98,
            Self::Cwe99 => CWE_99,
            Self::Cwe102 => CWE_102,
            Self::Cwe103 => CWE_103,
            Self::Cwe104 => CWE_104,
            Self::Cwe105 => CWE_105,
            Self::Cwe106 => CWE_106,
            Self::Cwe107 => CWE_107,
            Self::Cwe108 => CWE_108,
            Self::Cwe109 => CWE_109,
            Self::Cwe110 => CWE_110,
            Self::Cwe111 => CWE_111,
            Self::Cwe112 => CWE_112,
            Self::Cwe113 => CWE_113,
            Self::Cwe114 => CWE_114,
            Self::Cwe115 => CWE_115,
            Self::Cwe116 => CWE_116,
            Self::Cwe117 => CWE_117,
            Self::Cwe118 => CWE_118,
            Self::Cwe119 => CWE_119,
            Self::Cwe120 => CWE_120,
            Self::Cwe121 => CWE_121,
            Self::Cwe122 => CWE_122,
            Self::Cwe123 => CWE_123,
            Self::Cwe124 => CWE_124,
            Self::Cwe125 => CWE_125,
            Self::Cwe126 => CWE_126,
            Self::Cwe127 => CWE_127,
            Self::Cwe128 => CWE_128,
            Self::Cwe129 => CWE_129,
            Self::Cwe130 => CWE_130,
            Self::Cwe131 => CWE_131,
            Self::Cwe134 => CWE_134,
            Self::Cwe135 => CWE_135,
            Self::Cwe138 => CWE_138,
            Self::Cwe140 => CWE_140,
            Self::Cwe141 => CWE_141,
            Self::Cwe142 => CWE_142,
            Self::Cwe143 => CWE_143,
            Self::Cwe144 => CWE_144,
            Self::Cwe145 => CWE_145,
            Self::Cwe146 => CWE_146,
            Self::Cwe147 => CWE_147,
            Self::Cwe148 => CWE_148,
            Self::Cwe149 => CWE_149,
            Self::Cwe150 => CWE_150,
            Self::Cwe151 => CWE_151,
            Self::Cwe152 => CWE_152,
            Self::Cwe153 => CWE_153,
            Self::Cwe154 => CWE_154,
            Self::Cwe155 => CWE_155,
            Self::Cwe156 => CWE_156,
            Self::Cwe157 => CWE_157,
            Self::Cwe158 => CWE_158,
            Self::Cwe159 => CWE_159,
            Self::Cwe160 => CWE_160,
            Self::Cwe161 => CWE_161,
            Self::Cwe162 => CWE_162,
            Self::Cwe163 => CWE_163,
            Self::Cwe164 => CWE_164,
            Self::Cwe165 => CWE_165,
            Self::Cwe166 => CWE_166,
            Self::Cwe167 => CWE_167,
            Self::Cwe168 => CWE_168,
            Self::Cwe170 => CWE_170,
            Self::Cwe172 => CWE_172,
            Self::Cwe173 => CWE_173,
            Self::Cwe174 => CWE_174,
            Self::Cwe175 => CWE_175,
            Self::Cwe176 => CWE_176,
            Self::Cwe177 => CWE_177,
            Self::Cwe178 => CWE_178,
            Self::Cwe179 => CWE_179,
            Self::Cwe180 => CWE_180,
            Self::Cwe181 => CWE_181,
            Self::Cwe182 => CWE_182,
            Self::Cwe183 => CWE_183,
            Self::Cwe184 => CWE_184,
            Self::Cwe185 => CWE_185,
            Self::Cwe186 => CWE_186,
            Self::Cwe187 => CWE_187,
            Self::Cwe188 => CWE_188,
            Self::Cwe190 => CWE_190,
            Self::Cwe191 => CWE_191,
            Self::Cwe192 => CWE_192,
            Self::Cwe193 => CWE_193,
            Self::Cwe194 => CWE_194,
            Self::Cwe195 => CWE_195,
            Self::Cwe196 => CWE_196,
            Self::Cwe197 => CWE_197,
            Self::Cwe198 => CWE_198,
            Self::Cwe200 => CWE_200,
            Self::Cwe201 => CWE_201,
            Self::Cwe202 => CWE_202,
            Self::Cwe203 => CWE_203,
            Self::Cwe204 => CWE_204,
            Self::Cwe205 => CWE_205,
            Self::Cwe206 => CWE_206,
            Self::Cwe207 => CWE_207,
            Self::Cwe208 => CWE_208,
            Self::Cwe209 => CWE_209,
            Self::Cwe210 => CWE_210,
            Self::Cwe211 => CWE_211,
            Self::Cwe212 => CWE_212,
            Self::Cwe213 => CWE_213,
            Self::Cwe214 => CWE_214,
            Self::Cwe215 => CWE_215,
            Self::Cwe219 => CWE_219,
            Self::Cwe220 => CWE_220,
            Self::Cwe221 => CWE_221,
            Self::Cwe222 => CWE_222,
            Self::Cwe223 => CWE_223,
            Self::Cwe224 => CWE_224,
            Self::Cwe226 => CWE_226,
            Self::Cwe228 => CWE_228,
            Self::Cwe229 => CWE_229,
            Self::Cwe230 => CWE_230,
            Self::Cwe231 => CWE_231,
            Self::Cwe232 => CWE_232,
            Self::Cwe233 => CWE_233,
            Self::Cwe234 => CWE_234,
            Self::Cwe235 => CWE_235,
            Self::Cwe236 => CWE_236,
            Self::Cwe237 => CWE_237,
            Self::Cwe238 => CWE_238,
            Self::Cwe239 => CWE_239,
            Self::Cwe240 => CWE_240,
            Self::Cwe241 => CWE_241,
            Self::Cwe242 => CWE_242,
            Self::Cwe243 => CWE_243,
            Self::Cwe244 => CWE_244,
            Self::Cwe245 => CWE_245,
            Self::Cwe246 => CWE_246,
            Self::Cwe248 => CWE_248,
            Self::Cwe250 => CWE_250,
            Self::Cwe252 => CWE_252,
            Self::Cwe253 => CWE_253,
            Self::Cwe256 => CWE_256,
            Self::Cwe257 => CWE_257,
            Self::Cwe258 => CWE_258,
            Self::Cwe259 => CWE_259,
            Self::Cwe260 => CWE_260,
            Self::Cwe261 => CWE_261,
            Self::Cwe262 => CWE_262,
            Self::Cwe263 => CWE_263,
            Self::Cwe266 => CWE_266,
            Self::Cwe267 => CWE_267,
            Self::Cwe268 => CWE_268,
            Self::Cwe269 => CWE_269,
            Self::Cwe270 => CWE_270,
            Self::Cwe271 => CWE_271,
            Self::Cwe272 => CWE_272,
            Self::Cwe273 => CWE_273,
            Self::Cwe274 => CWE_274,
            Self::Cwe276 => CWE_276,
            Self::Cwe277 => CWE_277,
            Self::Cwe278 => CWE_278,
            Self::Cwe279 => CWE_279,
            Self::Cwe280 => CWE_280,
            Self::Cwe281 => CWE_281,
            Self::Cwe282 => CWE_282,
            Self::Cwe283 => CWE_283,
            Self::Cwe284 => CWE_284,
            Self::Cwe285 => CWE_285,
            Self::Cwe286 => CWE_286,
            Self::Cwe287 => CWE_287,
            Self::Cwe288 => CWE_288,
            Self::Cwe289 => CWE_289,
            Self::Cwe290 => CWE_290,
            Self::Cwe291 => CWE_291,
            Self::Cwe293 => CWE_293,
            Self::Cwe294 => CWE_294,
            Self::Cwe295 => CWE_295,
            Self::Cwe296 => CWE_296,
            Self::Cwe297 => CWE_297,
            Self::Cwe298 => CWE_298,
            Self::Cwe299 => CWE_299,
            Self::Cwe300 => CWE_300,
            Self::Cwe301 => CWE_301,
            Self::Cwe302 => CWE_302,
            Self::Cwe303 => CWE_303,
            Self::Cwe304 => CWE_304,
            Self::Cwe305 => CWE_305,
            Self::Cwe306 => CWE_306,
            Self::Cwe307 => CWE_307,
            Self::Cwe308 => CWE_308,
            Self::Cwe309 => CWE_309,
            Self::Cwe311 => CWE_311,
            Self::Cwe312 => CWE_312,
            Self::Cwe313 => CWE_313,
            Self::Cwe314 => CWE_314,
            Self::Cwe315 => CWE_315,
            Self::Cwe316 => CWE_316,
            Self::Cwe317 => CWE_317,
            Self::Cwe318 => CWE_318,
            Self::Cwe319 => CWE_319,
            Self::Cwe321 => CWE_321,
            Self::Cwe322 => CWE_322,
            Self::Cwe323 => CWE_323,
            Self::Cwe324 => CWE_324,
            Self::Cwe325 => CWE_325,
            Self::Cwe326 => CWE_326,
            Self::Cwe327 => CWE_327,
            Self::Cwe328 => CWE_328,
            Self::Cwe329 => CWE_329,
            Self::Cwe330 => CWE_330,
            Self::Cwe331 => CWE_331,
            Self::Cwe332 => CWE_332,
            Self::Cwe333 => CWE_333,
            Self::Cwe334 => CWE_334,
            Self::Cwe335 => CWE_335,
            Self::Cwe336 => CWE_336,
            Self::Cwe337 => CWE_337,
            Self::Cwe338 => CWE_338,
            Self::Cwe339 => CWE_339,
            Self::Cwe340 => CWE_340,
            Self::Cwe341 => CWE_341,
            Self::Cwe342 => CWE_342,
            Self::Cwe343 => CWE_343,
            Self::Cwe344 => CWE_344,
            Self::Cwe345 => CWE_345,
            Self::Cwe346 => CWE_346,
            Self::Cwe347 => CWE_347,
            Self::Cwe348 => CWE_348,
            Self::Cwe349 => CWE_349,
            Self::Cwe350 => CWE_350,
            Self::Cwe351 => CWE_351,
            Self::Cwe352 => CWE_352,
            Self::Cwe353 => CWE_353,
            Self::Cwe354 => CWE_354,
            Self::Cwe356 => CWE_356,
            Self::Cwe357 => CWE_357,
            Self::Cwe358 => CWE_358,
            Self::Cwe359 => CWE_359,
            Self::Cwe360 => CWE_360,
            Self::Cwe362 => CWE_362,
            Self::Cwe363 => CWE_363,
            Self::Cwe364 => CWE_364,
            Self::Cwe366 => CWE_366,
            Self::Cwe367 => CWE_367,
            Self::Cwe368 => CWE_368,
            Self::Cwe369 => CWE_369,
            Self::Cwe370 => CWE_370,
            Self::Cwe372 => CWE_372,
            Self::Cwe374 => CWE_374,
            Self::Cwe375 => CWE_375,
            Self::Cwe377 => CWE_377,
            Self::Cwe378 => CWE_378,
            Self::Cwe379 => CWE_379,
            Self::Cwe382 => CWE_382,
            Self::Cwe383 => CWE_383,
            Self::Cwe384 => CWE_384,
            Self::Cwe385 => CWE_385,
            Self::Cwe386 => CWE_386,
            Self::Cwe390 => CWE_390,
            Self::Cwe391 => CWE_391,
            Self::Cwe392 => CWE_392,
            Self::Cwe393 => CWE_393,
            Self::Cwe394 => CWE_394,
            Self::Cwe395 => CWE_395,
            Self::Cwe396 => CWE_396,
            Self::Cwe397 => CWE_397,
            Self::Cwe400 => CWE_400,
            Self::Cwe401 => CWE_401,
            Self::Cwe402 => CWE_402,
            Self::Cwe403 => CWE_403,
            Self::Cwe404 => CWE_404,
            Self::Cwe405 => CWE_405,
            Self::Cwe406 => CWE_406,
            Self::Cwe407 => CWE_407,
            Self::Cwe408 => CWE_408,
            Self::Cwe409 => CWE_409,
            Self::Cwe410 => CWE_410,
            Self::Cwe412 => CWE_412,
            Self::Cwe413 => CWE_413,
            Self::Cwe414 => CWE_414,
            Self::Cwe415 => CWE_415,
            Self::Cwe416 => CWE_416,
            Self::Cwe419 => CWE_419,
            Self::Cwe420 => CWE_420,
            Self::Cwe421 => CWE_421,
            Self::Cwe422 => CWE_422,
            Self::Cwe424 => CWE_424,
            Self::Cwe425 => CWE_425,
            Self::Cwe426 => CWE_426,
            Self::Cwe427 => CWE_427,
            Self::Cwe428 => CWE_428,
            Self::Cwe430 => CWE_430,
            Self::Cwe431 => CWE_431,
            Self::Cwe432 => CWE_432,
            Self::Cwe433 => CWE_433,
            Self::Cwe434 => CWE_434,
            Self::Cwe435 => CWE_435,
            Self::Cwe436 => CWE_436,
            Self::Cwe437 => CWE_437,
            Self::Cwe439 => CWE_439,
            Self::Cwe440 => CWE_440,
            Self::Cwe441 => CWE_441,
            Self::Cwe444 => CWE_444,
            Self::Cwe446 => CWE_446,
            Self::Cwe447 => CWE_447,
            Self::Cwe448 => CWE_448,
            Self::Cwe449 => CWE_449,
            Self::Cwe450 => CWE_450,
            Self::Cwe451 => CWE_451,
            Self::Cwe453 => CWE_453,
            Self::Cwe454 => CWE_454,
            Self::Cwe455 => CWE_455,
            Self::Cwe456 => CWE_456,
            Self::Cwe457 => CWE_457,
            Self::Cwe459 => CWE_459,
            Self::Cwe460 => CWE_460,
            Self::Cwe462 => CWE_462,
            Self::Cwe463 => CWE_463,
            Self::Cwe464 => CWE_464,
            Self::Cwe466 => CWE_466,
            Self::Cwe467 => CWE_467,
            Self::Cwe468 => CWE_468,
            Self::Cwe469 => CWE_469,
            Self::Cwe470 => CWE_470,
            Self::Cwe471 => CWE_471,
            Self::Cwe472 => CWE_472,
            Self::Cwe473 => CWE_473,
            Self::Cwe474 => CWE_474,
            Self::Cwe475 => CWE_475,
            Self::Cwe476 => CWE_476,
            Self::Cwe477 => CWE_477,
            Self::Cwe478 => CWE_478,
            Self::Cwe479 => CWE_479,
            Self::Cwe480 => CWE_480,
            Self::Cwe481 => CWE_481,
            Self::Cwe482 => CWE_482,
            Self::Cwe483 => CWE_483,
            Self::Cwe484 => CWE_484,
            Self::Cwe486 => CWE_486,
            Self::Cwe487 => CWE_487,
            Self::Cwe488 => CWE_488,
            Self::Cwe489 => CWE_489,
            Self::Cwe491 => CWE_491,
            Self::Cwe492 => CWE_492,
            Self::Cwe493 => CWE_493,
            Self::Cwe494 => CWE_494,
            Self::Cwe495 => CWE_495,
            Self::Cwe496 => CWE_496,
            Self::Cwe497 => CWE_497,
            Self::Cwe498 => CWE_498,
            Self::Cwe499 => CWE_499,
            Self::Cwe500 => CWE_500,
            Self::Cwe501 => CWE_501,
            Self::Cwe502 => CWE_502,
            Self::Cwe506 => CWE_506,
            Self::Cwe507 => CWE_507,
            Self::Cwe508 => CWE_508,
            Self::Cwe509 => CWE_509,
            Self::Cwe510 => CWE_510,
            Self::Cwe511 => CWE_511,
            Self::Cwe512 => CWE_512,
            Self::Cwe514 => CWE_514,
            Self::Cwe515 => CWE_515,
            Self::Cwe520 => CWE_520,
            Self::Cwe521 => CWE_521,
            Self::Cwe522 => CWE_522,
            Self::Cwe523 => CWE_523,
            Self::Cwe524 => CWE_524,
            Self::Cwe525 => CWE_525,
            Self::Cwe526 => CWE_526,
            Self::Cwe527 => CWE_527,
            Self::Cwe528 => CWE_528,
            Self::Cwe529 => CWE_529,
            Self::Cwe530 => CWE_530,
            Self::Cwe531 => CWE_531,
            Self::Cwe532 => CWE_532,
            Self::Cwe535 => CWE_535,
            Self::Cwe536 => CWE_536,
            Self::Cwe537 => CWE_537,
            Self::Cwe538 => CWE_538,
            Self::Cwe539 => CWE_539,
            Self::Cwe540 => CWE_540,
            Self::Cwe541 => CWE_541,
            Self::Cwe543 => CWE_543,
            Self::Cwe544 => CWE_544,
            Self::Cwe546 => CWE_546,
            Self::Cwe547 => CWE_547,
            Self::Cwe548 => CWE_548,
            Self::Cwe549 => CWE_549,
            Self::Cwe550 => CWE_550,
            Self::Cwe551 => CWE_551,
            Self::Cwe552 => CWE_552,
            Self::Cwe553 => CWE_553,
            Self::Cwe554 => CWE_554,
            Self::Cwe555 => CWE_555,
            Self::Cwe556 => CWE_556,
            Self::Cwe558 => CWE_558,
            Self::Cwe560 => CWE_560,
            Self::Cwe561 => CWE_561,
            Self::Cwe562 => CWE_562,
            Self::Cwe563 => CWE_563,
            Self::Cwe564 => CWE_564,
            Self::Cwe565 => CWE_565,
            Self::Cwe566 => CWE_566,
            Self::Cwe567 => CWE_567,
            Self::Cwe568 => CWE_568,
            Self::Cwe570 => CWE_570,
            Self::Cwe571 => CWE_571,
            Self::Cwe572 => CWE_572,
            Self::Cwe573 => CWE_573,
            Self::Cwe574 => CWE_574,
            Self::Cwe575 => CWE_575,
            Self::Cwe576 => CWE_576,
            Self::Cwe577 => CWE_577,
            Self::Cwe578 => CWE_578,
            Self::Cwe579 => CWE_579,
            Self::Cwe580 => CWE_580,
            Self::Cwe581 => CWE_581,
            Self::Cwe582 => CWE_582,
            Self::Cwe583 => CWE_583,
            Self::Cwe584 => CWE_584,
            Self::Cwe585 => CWE_585,
            Self::Cwe586 => CWE_586,
            Self::Cwe587 => CWE_587,
            Self::Cwe588 => CWE_588,
            Self::Cwe589 => CWE_589,
            Self::Cwe590 => CWE_590,
            Self::Cwe591 => CWE_591,
            Self::Cwe593 => CWE_593,
            Self::Cwe594 => CWE_594,
            Self::Cwe595 => CWE_595,
            Self::Cwe597 => CWE_597,
            Self::Cwe598 => CWE_598,
            Self::Cwe599 => CWE_599,
            Self::Cwe600 => CWE_600,
            Self::Cwe601 => CWE_601,
            Self::Cwe602 => CWE_602,
            Self::Cwe603 => CWE_603,
            Self::Cwe605 => CWE_605,
            Self::Cwe606 => CWE_606,
            Self::Cwe607 => CWE_607,
            Self::Cwe608 => CWE_608,
            Self::Cwe609 => CWE_609,
            Self::Cwe610 => CWE_610,
            Self::Cwe611 => CWE_611,
            Self::Cwe612 => CWE_612,
            Self::Cwe613 => CWE_613,
            Self::Cwe614 => CWE_614,
            Self::Cwe615 => CWE_615,
            Self::Cwe616 => CWE_616,
            Self::Cwe617 => CWE_617,
            Self::Cwe618 => CWE_618,
            Self::Cwe619 => CWE_619,
            Self::Cwe620 => CWE_620,
            Self::Cwe621 => CWE_621,
            Self::Cwe622 => CWE_622,
            Self::Cwe623 => CWE_623,
            Self::Cwe624 => CWE_624,
            Self::Cwe625 => CWE_625,
            Self::Cwe626 => CWE_626,
            Self::Cwe627 => CWE_627,
            Self::Cwe628 => CWE_628,
            Self::Cwe636 => CWE_636,
            Self::Cwe637 => CWE_637,
            Self::Cwe638 => CWE_638,
            Self::Cwe639 => CWE_639,
            Self::Cwe640 => CWE_640,
            Self::Cwe641 => CWE_641,
            Self::Cwe642 => CWE_642,
            Self::Cwe643 => CWE_643,
            Self::Cwe644 => CWE_644,
            Self::Cwe645 => CWE_645,
            Self::Cwe646 => CWE_646,
            Self::Cwe647 => CWE_647,
            Self::Cwe648 => CWE_648,
            Self::Cwe649 => CWE_649,
            Self::Cwe650 => CWE_650,
            Self::Cwe651 => CWE_651,
            Self::Cwe652 => CWE_652,
            Self::Cwe653 => CWE_653,
            Self::Cwe654 => CWE_654,
            Self::Cwe655 => CWE_655,
            Self::Cwe656 => CWE_656,
            Self::Cwe657 => CWE_657,
            Self::Cwe662 => CWE_662,
            Self::Cwe663 => CWE_663,
            Self::Cwe664 => CWE_664,
            Self::Cwe665 => CWE_665,
            Self::Cwe666 => CWE_666,
            Self::Cwe667 => CWE_667,
            Self::Cwe668 => CWE_668,
            Self::Cwe669 => CWE_669,
            Self::Cwe670 => CWE_670,
            Self::Cwe671 => CWE_671,
            Self::Cwe672 => CWE_672,
            Self::Cwe673 => CWE_673,
            Self::Cwe674 => CWE_674,
            Self::Cwe675 => CWE_675,
            Self::Cwe676 => CWE_676,
            Self::Cwe680 => CWE_680,
            Self::Cwe681 => CWE_681,
            Self::Cwe682 => CWE_682,
            Self::Cwe683 => CWE_683,
            Self::Cwe684 => CWE_684,
            Self::Cwe685 => CWE_685,
            Self::Cwe686 => CWE_686,
            Self::Cwe687 => CWE_687,
            Self::Cwe688 => CWE_688,
            Self::Cwe689 => CWE_689,
            Self::Cwe690 => CWE_690,
            Self::Cwe691 => CWE_691,
            Self::Cwe692 => CWE_692,
            Self::Cwe693 => CWE_693,
            Self::Cwe694 => CWE_694,
            Self::Cwe695 => CWE_695,
            Self::Cwe696 => CWE_696,
            Self::Cwe697 => CWE_697,
            Self::Cwe698 => CWE_698,
            Self::Cwe703 => CWE_703,
            Self::Cwe704 => CWE_704,
            Self::Cwe705 => CWE_705,
            Self::Cwe706 => CWE_706,
            Self::Cwe707 => CWE_707,
            Self::Cwe708 => CWE_708,
            Self::Cwe710 => CWE_710,
            Self::Cwe732 => CWE_732,
            Self::Cwe733 => CWE_733,
            Self::Cwe749 => CWE_749,
            Self::Cwe754 => CWE_754,
            Self::Cwe755 => CWE_755,
            Self::Cwe756 => CWE_756,
            Self::Cwe757 => CWE_757,
            Self::Cwe758 => CWE_758,
            Self::Cwe759 => CWE_759,
            Self::Cwe760 => CWE_760,
            Self::Cwe761 => CWE_761,
            Self::Cwe762 => CWE_762,
            Self::Cwe763 => CWE_763,
            Self::Cwe764 => CWE_764,
            Self::Cwe765 => CWE_765,
            Self::Cwe766 => CWE_766,
            Self::Cwe767 => CWE_767,
            Self::Cwe768 => CWE_768,
            Self::Cwe770 => CWE_770,
            Self::Cwe771 => CWE_771,
            Self::Cwe772 => CWE_772,
            Self::Cwe773 => CWE_773,
            Self::Cwe774 => CWE_774,
            Self::Cwe775 => CWE_775,
            Self::Cwe776 => CWE_776,
            Self::Cwe777 => CWE_777,
            Self::Cwe778 => CWE_778,
            Self::Cwe779 => CWE_779,
            Self::Cwe780 => CWE_780,
            Self::Cwe781 => CWE_781,
            Self::Cwe782 => CWE_782,
            Self::Cwe783 => CWE_783,
            Self::Cwe784 => CWE_784,
            Self::Cwe785 => CWE_785,
            Self::Cwe786 => CWE_786,
            Self::Cwe787 => CWE_787,
            Self::Cwe788 => CWE_788,
            Self::Cwe789 => CWE_789,
            Self::Cwe790 => CWE_790,
            Self::Cwe791 => CWE_791,
            Self::Cwe792 => CWE_792,
            Self::Cwe793 => CWE_793,
            Self::Cwe794 => CWE_794,
            Self::Cwe795 => CWE_795,
            Self::Cwe796 => CWE_796,
            Self::Cwe797 => CWE_797,
            Self::Cwe798 => CWE_798,
            Self::Cwe799 => CWE_799,
            Self::Cwe804 => CWE_804,
            Self::Cwe805 => CWE_805,
            Self::Cwe806 => CWE_806,
            Self::Cwe807 => CWE_807,
            Self::Cwe820 => CWE_820,
            Self::Cwe821 => CWE_821,
            Self::Cwe822 => CWE_822,
            Self::Cwe823 => CWE_823,
            Self::Cwe824 => CWE_824,
            Self::Cwe825 => CWE_825,
            Self::Cwe826 => CWE_826,
            Self::Cwe827 => CWE_827,
            Self::Cwe828 => CWE_828,
            Self::Cwe829 => CWE_829,
            Self::Cwe830 => CWE_830,
            Self::Cwe831 => CWE_831,
            Self::Cwe832 => CWE_832,
            Self::Cwe833 => CWE_833,
            Self::Cwe834 => CWE_834,
            Self::Cwe835 => CWE_835,
            Self::Cwe836 => CWE_836,
            Self::Cwe837 => CWE_837,
            Self::Cwe838 => CWE_838,
            Self::Cwe839 => CWE_839,
            Self::Cwe841 => CWE_841,
            Self::Cwe842 => CWE_842,
            Self::Cwe843 => CWE_843,
            Self::Cwe862 => CWE_862,
            Self::Cwe863 => CWE_863,
            Self::Cwe908 => CWE_908,
            Self::Cwe909 => CWE_909,
            Self::Cwe910 => CWE_910,
            Self::Cwe911 => CWE_911,
            Self::Cwe912 => CWE_912,
            Self::Cwe913 => CWE_913,
            Self::Cwe914 => CWE_914,
            Self::Cwe915 => CWE_915,
            Self::Cwe916 => CWE_916,
            Self::Cwe917 => CWE_917,
            Self::Cwe918 => CWE_918,
            Self::Cwe920 => CWE_920,
            Self::Cwe921 => CWE_921,
            Self::Cwe922 => CWE_922,
            Self::Cwe923 => CWE_923,
            Self::Cwe924 => CWE_924,
            Self::Cwe925 => CWE_925,
            Self::Cwe926 => CWE_926,
            Self::Cwe927 => CWE_927,
            Self::Cwe939 => CWE_939,
            Self::Cwe940 => CWE_940,
            Self::Cwe941 => CWE_941,
            Self::Cwe942 => CWE_942,
            Self::Cwe943 => CWE_943,
            Self::Cwe1004 => CWE_1004,
            Self::Cwe1007 => CWE_1007,
            Self::Cwe1021 => CWE_1021,
            Self::Cwe1022 => CWE_1022,
            Self::Cwe1023 => CWE_1023,
            Self::Cwe1024 => CWE_1024,
            Self::Cwe1025 => CWE_1025,
            Self::Cwe1037 => CWE_1037,
            Self::Cwe1038 => CWE_1038,
            Self::Cwe1039 => CWE_1039,
            Self::Cwe1041 => CWE_1041,
            Self::Cwe1042 => CWE_1042,
            Self::Cwe1043 => CWE_1043,
            Self::Cwe1044 => CWE_1044,
            Self::Cwe1045 => CWE_1045,
            Self::Cwe1046 => CWE_1046,
            Self::Cwe1047 => CWE_1047,
            Self::Cwe1048 => CWE_1048,
            Self::Cwe1049 => CWE_1049,
            Self::Cwe1050 => CWE_1050,
            Self::Cwe1051 => CWE_1051,
            Self::Cwe1052 => CWE_1052,
            Self::Cwe1053 => CWE_1053,
            Self::Cwe1054 => CWE_1054,
            Self::Cwe1055 => CWE_1055,
            Self::Cwe1056 => CWE_1056,
            Self::Cwe1057 => CWE_1057,
            Self::Cwe1058 => CWE_1058,
            Self::Cwe1059 => CWE_1059,
            Self::Cwe1060 => CWE_1060,
            Self::Cwe1061 => CWE_1061,
            Self::Cwe1062 => CWE_1062,
            Self::Cwe1063 => CWE_1063,
            Self::Cwe1064 => CWE_1064,
            Self::Cwe1065 => CWE_1065,
            Self::Cwe1066 => CWE_1066,
            Self::Cwe1067 => CWE_1067,
            Self::Cwe1068 => CWE_1068,
            Self::Cwe1069 => CWE_1069,
            Self::Cwe1070 => CWE_1070,
            Self::Cwe1071 => CWE_1071,
            Self::Cwe1072 => CWE_1072,
            Self::Cwe1073 => CWE_1073,
            Self::Cwe1074 => CWE_1074,
            Self::Cwe1075 => CWE_1075,
            Self::Cwe1076 => CWE_1076,
            Self::Cwe1077 => CWE_1077,
            Self::Cwe1078 => CWE_1078,
            Self::Cwe1079 => CWE_1079,
            Self::Cwe1080 => CWE_1080,
            Self::Cwe1082 => CWE_1082,
            Self::Cwe1083 => CWE_1083,
            Self::Cwe1084 => CWE_1084,
            Self::Cwe1085 => CWE_1085,
            Self::Cwe1086 => CWE_1086,
            Self::Cwe1087 => CWE_1087,
            Self::Cwe1088 => CWE_1088,
            Self::Cwe1089 => CWE_1089,
            Self::Cwe1090 => CWE_1090,
            Self::Cwe1091 => CWE_1091,
            Self::Cwe1092 => CWE_1092,
            Self::Cwe1093 => CWE_1093,
            Self::Cwe1094 => CWE_1094,
            Self::Cwe1095 => CWE_1095,
            Self::Cwe1096 => CWE_1096,
            Self::Cwe1097 => CWE_1097,
            Self::Cwe1098 => CWE_1098,
            Self::Cwe1099 => CWE_1099,
            Self::Cwe1100 => CWE_1100,
            Self::Cwe1101 => CWE_1101,
            Self::Cwe1102 => CWE_1102,
            Self::Cwe1103 => CWE_1103,
            Self::Cwe1104 => CWE_1104,
            Self::Cwe1105 => CWE_1105,
            Self::Cwe1106 => CWE_1106,
            Self::Cwe1107 => CWE_1107,
            Self::Cwe1108 => CWE_1108,
            Self::Cwe1109 => CWE_1109,
            Self::Cwe1110 => CWE_1110,
            Self::Cwe1111 => CWE_1111,
            Self::Cwe1112 => CWE_1112,
            Self::Cwe1113 => CWE_1113,
            Self::Cwe1114 => CWE_1114,
            Self::Cwe1115 => CWE_1115,
            Self::Cwe1116 => CWE_1116,
            Self::Cwe1117 => CWE_1117,
            Self::Cwe1118 => CWE_1118,
            Self::Cwe1119 => CWE_1119,
            Self::Cwe1120 => CWE_1120,
            Self::Cwe1121 => CWE_1121,
            Self::Cwe1122 => CWE_1122,
            Self::Cwe1123 => CWE_1123,
            Self::Cwe1124 => CWE_1124,
            Self::Cwe1125 => CWE_1125,
            Self::Cwe1126 => CWE_1126,
            Self::Cwe1127 => CWE_1127,
            Self::Cwe1164 => CWE_1164,
            Self::Cwe1173 => CWE_1173,
            Self::Cwe1174 => CWE_1174,
            Self::Cwe1176 => CWE_1176,
            Self::Cwe1177 => CWE_1177,
            Self::Cwe1188 => CWE_1188,
            Self::Cwe1189 => CWE_1189,
            Self::Cwe1190 => CWE_1190,
            Self::Cwe1191 => CWE_1191,
            Self::Cwe1192 => CWE_1192,
            Self::Cwe1193 => CWE_1193,
            Self::Cwe1204 => CWE_1204,
            Self::Cwe1209 => CWE_1209,
            Self::Cwe1220 => CWE_1220,
            Self::Cwe1221 => CWE_1221,
            Self::Cwe1222 => CWE_1222,
            Self::Cwe1223 => CWE_1223,
            Self::Cwe1224 => CWE_1224,
            Self::Cwe1229 => CWE_1229,
            Self::Cwe1230 => CWE_1230,
            Self::Cwe1231 => CWE_1231,
            Self::Cwe1232 => CWE_1232,
            Self::Cwe1233 => CWE_1233,
            Self::Cwe1234 => CWE_1234,
            Self::Cwe1235 => CWE_1235,
            Self::Cwe1236 => CWE_1236,
            Self::Cwe1239 => CWE_1239,
            Self::Cwe1240 => CWE_1240,
            Self::Cwe1241 => CWE_1241,
            Self::Cwe1242 => CWE_1242,
            Self::Cwe1243 => CWE_1243,
            Self::Cwe1244 => CWE_1244,
            Self::Cwe1245 => CWE_1245,
            Self::Cwe1246 => CWE_1246,
            Self::Cwe1247 => CWE_1247,
            Self::Cwe1248 => CWE_1248,
            Self::Cwe1249 => CWE_1249,
            Self::Cwe1250 => CWE_1250,
            Self::Cwe1251 => CWE_1251,
            Self::Cwe1252 => CWE_1252,
            Self::Cwe1253 => CWE_1253,
            Self::Cwe1254 => CWE_1254,
            Self::Cwe1255 => CWE_1255,
            Self::Cwe1256 => CWE_1256,
            Self::Cwe1257 => CWE_1257,
            Self::Cwe1258 => CWE_1258,
            Self::Cwe1259 => CWE_1259,
            Self::Cwe1260 => CWE_1260,
            Self::Cwe1261 => CWE_1261,
            Self::Cwe1262 => CWE_1262,
            Self::Cwe1263 => CWE_1263,
            Self::Cwe1264 => CWE_1264,
            Self::Cwe1265 => CWE_1265,
            Self::Cwe1266 => CWE_1266,
            Self::Cwe1267 => CWE_1267,
            Self::Cwe1268 => CWE_1268,
            Self::Cwe1269 => CWE_1269,
            Self::Cwe1270 => CWE_1270,
            Self::Cwe1271 => CWE_1271,
            Self::Cwe1272 => CWE_1272,
            Self::Cwe1273 => CWE_1273,
            Self::Cwe1274 => CWE_1274,
            Self::Cwe1275 => CWE_1275,
            Self::Cwe1276 => CWE_1276,
            Self::Cwe1277 => CWE_1277,
            Self::Cwe1278 => CWE_1278,
            Self::Cwe1279 => CWE_1279,
            Self::Cwe1280 => CWE_1280,
            Self::Cwe1281 => CWE_1281,
            Self::Cwe1282 => CWE_1282,
            Self::Cwe1283 => CWE_1283,
            Self::Cwe1284 => CWE_1284,
            Self::Cwe1285 => CWE_1285,
            Self::Cwe1286 => CWE_1286,
            Self::Cwe1287 => CWE_1287,
            Self::Cwe1288 => CWE_1288,
            Self::Cwe1289 => CWE_1289,
            Self::Cwe1290 => CWE_1290,
            Self::Cwe1291 => CWE_1291,
            Self::Cwe1292 => CWE_1292,
            Self::Cwe1293 => CWE_1293,
            Self::Cwe1294 => CWE_1294,
            Self::Cwe1295 => CWE_1295,
            Self::Cwe1296 => CWE_1296,
            Self::Cwe1297 => CWE_1297,
            Self::Cwe1298 => CWE_1298,
            Self::Cwe1299 => CWE_1299,
            Self::Cwe1300 => CWE_1300,
            Self::Cwe1301 => CWE_1301,
            Self::Cwe1302 => CWE_1302,
            Self::Cwe1303 => CWE_1303,
            Self::Cwe1304 => CWE_1304,
            Self::Cwe1310 => CWE_1310,
            Self::Cwe1311 => CWE_1311,
            Self::Cwe1312 => CWE_1312,
            Self::Cwe1313 => CWE_1313,
            Self::Cwe1314 => CWE_1314,
            Self::Cwe1315 => CWE_1315,
            Self::Cwe1316 => CWE_1316,
            Self::Cwe1317 => CWE_1317,
            Self::Cwe1318 => CWE_1318,
            Self::Cwe1319 => CWE_1319,
            Self::Cwe1320 => CWE_1320,
            Self::Cwe1321 => CWE_1321,
            Self::Cwe1322 => CWE_1322,
            Self::Cwe1323 => CWE_1323,
            Self::Cwe1325 => CWE_1325,
            Self::Cwe1326 => CWE_1326,
            Self::Cwe1327 => CWE_1327,
            Self::Cwe1328 => CWE_1328,
            Self::Cwe1329 => CWE_1329,
            Self::Cwe1330 => CWE_1330,
            Self::Cwe1331 => CWE_1331,
            Self::Cwe1332 => CWE_1332,
            Self::Cwe1333 => CWE_1333,
            Self::Cwe1334 => CWE_1334,
            Self::Cwe1335 => CWE_1335,
            Self::Cwe1336 => CWE_1336,
            Self::Cwe1338 => CWE_1338,
            Self::Cwe1339 => CWE_1339,
            Self::Cwe1341 => CWE_1341,
            Self::Cwe1342 => CWE_1342,
            Self::Cwe1351 => CWE_1351,
            Self::Cwe1357 => CWE_1357,
            Self::Cwe1384 => CWE_1384,
            Self::Cwe1385 => CWE_1385,
            Self::Cwe1386 => CWE_1386,
            Self::Cwe1389 => CWE_1389,
            Self::Cwe1390 => CWE_1390,
            Self::Cwe1391 => CWE_1391,
            Self::Cwe1392 => CWE_1392,
            Self::Cwe1393 => CWE_1393,
            Self::Cwe1394 => CWE_1394,
            Self::Cwe1395 => CWE_1395,
            Self::Cwe1419 => CWE_1419,
        }
    }
}

#[derive(Debug, Error)]
#[error("cannot parse as a valid CWE ID")]
pub struct CWEParseError;

impl FromStr for CWE {
    type Err = CWEParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = s.strip_prefix("CWE-").ok_or(CWEParseError)?;
        let value = match id {
            "5" => Self::Cwe5,
            "6" => Self::Cwe6,
            "7" => Self::Cwe7,
            "8" => Self::Cwe8,
            "9" => Self::Cwe9,
            "11" => Self::Cwe11,
            "12" => Self::Cwe12,
            "13" => Self::Cwe13,
            "14" => Self::Cwe14,
            "15" => Self::Cwe15,
            "20" => Self::Cwe20,
            "22" => Self::Cwe22,
            "23" => Self::Cwe23,
            "24" => Self::Cwe24,
            "25" => Self::Cwe25,
            "26" => Self::Cwe26,
            "27" => Self::Cwe27,
            "28" => Self::Cwe28,
            "29" => Self::Cwe29,
            "30" => Self::Cwe30,
            "31" => Self::Cwe31,
            "32" => Self::Cwe32,
            "33" => Self::Cwe33,
            "34" => Self::Cwe34,
            "35" => Self::Cwe35,
            "36" => Self::Cwe36,
            "37" => Self::Cwe37,
            "38" => Self::Cwe38,
            "39" => Self::Cwe39,
            "40" => Self::Cwe40,
            "41" => Self::Cwe41,
            "42" => Self::Cwe42,
            "43" => Self::Cwe43,
            "44" => Self::Cwe44,
            "45" => Self::Cwe45,
            "46" => Self::Cwe46,
            "47" => Self::Cwe47,
            "48" => Self::Cwe48,
            "49" => Self::Cwe49,
            "50" => Self::Cwe50,
            "51" => Self::Cwe51,
            "52" => Self::Cwe52,
            "53" => Self::Cwe53,
            "54" => Self::Cwe54,
            "55" => Self::Cwe55,
            "56" => Self::Cwe56,
            "57" => Self::Cwe57,
            "58" => Self::Cwe58,
            "59" => Self::Cwe59,
            "61" => Self::Cwe61,
            "62" => Self::Cwe62,
            "64" => Self::Cwe64,
            "65" => Self::Cwe65,
            "66" => Self::Cwe66,
            "67" => Self::Cwe67,
            "69" => Self::Cwe69,
            "72" => Self::Cwe72,
            "73" => Self::Cwe73,
            "74" => Self::Cwe74,
            "75" => Self::Cwe75,
            "76" => Self::Cwe76,
            "77" => Self::Cwe77,
            "78" => Self::Cwe78,
            "79" => Self::Cwe79,
            "80" => Self::Cwe80,
            "81" => Self::Cwe81,
            "82" => Self::Cwe82,
            "83" => Self::Cwe83,
            "84" => Self::Cwe84,
            "85" => Self::Cwe85,
            "86" => Self::Cwe86,
            "87" => Self::Cwe87,
            "88" => Self::Cwe88,
            "89" => Self::Cwe89,
            "90" => Self::Cwe90,
            "91" => Self::Cwe91,
            "93" => Self::Cwe93,
            "94" => Self::Cwe94,
            "95" => Self::Cwe95,
            "96" => Self::Cwe96,
            "97" => Self::Cwe97,
            "98" => Self::Cwe98,
            "99" => Self::Cwe99,
            "102" => Self::Cwe102,
            "103" => Self::Cwe103,
            "104" => Self::Cwe104,
            "105" => Self::Cwe105,
            "106" => Self::Cwe106,
            "107" => Self::Cwe107,
            "108" => Self::Cwe108,
            "109" => Self::Cwe109,
            "110" => Self::Cwe110,
            "111" => Self::Cwe111,
            "112" => Self::Cwe112,
            "113" => Self::Cwe113,
            "114" => Self::Cwe114,
            "115" => Self::Cwe115,
            "116" => Self::Cwe116,
            "117" => Self::Cwe117,
            "118" => Self::Cwe118,
            "119" => Self::Cwe119,
            "120" => Self::Cwe120,
            "121" => Self::Cwe121,
            "122" => Self::Cwe122,
            "123" => Self::Cwe123,
            "124" => Self::Cwe124,
            "125" => Self::Cwe125,
            "126" => Self::Cwe126,
            "127" => Self::Cwe127,
            "128" => Self::Cwe128,
            "129" => Self::Cwe129,
            "130" => Self::Cwe130,
            "131" => Self::Cwe131,
            "134" => Self::Cwe134,
            "135" => Self::Cwe135,
            "138" => Self::Cwe138,
            "140" => Self::Cwe140,
            "141" => Self::Cwe141,
            "142" => Self::Cwe142,
            "143" => Self::Cwe143,
            "144" => Self::Cwe144,
            "145" => Self::Cwe145,
            "146" => Self::Cwe146,
            "147" => Self::Cwe147,
            "148" => Self::Cwe148,
            "149" => Self::Cwe149,
            "150" => Self::Cwe150,
            "151" => Self::Cwe151,
            "152" => Self::Cwe152,
            "153" => Self::Cwe153,
            "154" => Self::Cwe154,
            "155" => Self::Cwe155,
            "156" => Self::Cwe156,
            "157" => Self::Cwe157,
            "158" => Self::Cwe158,
            "159" => Self::Cwe159,
            "160" => Self::Cwe160,
            "161" => Self::Cwe161,
            "162" => Self::Cwe162,
            "163" => Self::Cwe163,
            "164" => Self::Cwe164,
            "165" => Self::Cwe165,
            "166" => Self::Cwe166,
            "167" => Self::Cwe167,
            "168" => Self::Cwe168,
            "170" => Self::Cwe170,
            "172" => Self::Cwe172,
            "173" => Self::Cwe173,
            "174" => Self::Cwe174,
            "175" => Self::Cwe175,
            "176" => Self::Cwe176,
            "177" => Self::Cwe177,
            "178" => Self::Cwe178,
            "179" => Self::Cwe179,
            "180" => Self::Cwe180,
            "181" => Self::Cwe181,
            "182" => Self::Cwe182,
            "183" => Self::Cwe183,
            "184" => Self::Cwe184,
            "185" => Self::Cwe185,
            "186" => Self::Cwe186,
            "187" => Self::Cwe187,
            "188" => Self::Cwe188,
            "190" => Self::Cwe190,
            "191" => Self::Cwe191,
            "192" => Self::Cwe192,
            "193" => Self::Cwe193,
            "194" => Self::Cwe194,
            "195" => Self::Cwe195,
            "196" => Self::Cwe196,
            "197" => Self::Cwe197,
            "198" => Self::Cwe198,
            "200" => Self::Cwe200,
            "201" => Self::Cwe201,
            "202" => Self::Cwe202,
            "203" => Self::Cwe203,
            "204" => Self::Cwe204,
            "205" => Self::Cwe205,
            "206" => Self::Cwe206,
            "207" => Self::Cwe207,
            "208" => Self::Cwe208,
            "209" => Self::Cwe209,
            "210" => Self::Cwe210,
            "211" => Self::Cwe211,
            "212" => Self::Cwe212,
            "213" => Self::Cwe213,
            "214" => Self::Cwe214,
            "215" => Self::Cwe215,
            "219" => Self::Cwe219,
            "220" => Self::Cwe220,
            "221" => Self::Cwe221,
            "222" => Self::Cwe222,
            "223" => Self::Cwe223,
            "224" => Self::Cwe224,
            "226" => Self::Cwe226,
            "228" => Self::Cwe228,
            "229" => Self::Cwe229,
            "230" => Self::Cwe230,
            "231" => Self::Cwe231,
            "232" => Self::Cwe232,
            "233" => Self::Cwe233,
            "234" => Self::Cwe234,
            "235" => Self::Cwe235,
            "236" => Self::Cwe236,
            "237" => Self::Cwe237,
            "238" => Self::Cwe238,
            "239" => Self::Cwe239,
            "240" => Self::Cwe240,
            "241" => Self::Cwe241,
            "242" => Self::Cwe242,
            "243" => Self::Cwe243,
            "244" => Self::Cwe244,
            "245" => Self::Cwe245,
            "246" => Self::Cwe246,
            "248" => Self::Cwe248,
            "250" => Self::Cwe250,
            "252" => Self::Cwe252,
            "253" => Self::Cwe253,
            "256" => Self::Cwe256,
            "257" => Self::Cwe257,
            "258" => Self::Cwe258,
            "259" => Self::Cwe259,
            "260" => Self::Cwe260,
            "261" => Self::Cwe261,
            "262" => Self::Cwe262,
            "263" => Self::Cwe263,
            "266" => Self::Cwe266,
            "267" => Self::Cwe267,
            "268" => Self::Cwe268,
            "269" => Self::Cwe269,
            "270" => Self::Cwe270,
            "271" => Self::Cwe271,
            "272" => Self::Cwe272,
            "273" => Self::Cwe273,
            "274" => Self::Cwe274,
            "276" => Self::Cwe276,
            "277" => Self::Cwe277,
            "278" => Self::Cwe278,
            "279" => Self::Cwe279,
            "280" => Self::Cwe280,
            "281" => Self::Cwe281,
            "282" => Self::Cwe282,
            "283" => Self::Cwe283,
            "284" => Self::Cwe284,
            "285" => Self::Cwe285,
            "286" => Self::Cwe286,
            "287" => Self::Cwe287,
            "288" => Self::Cwe288,
            "289" => Self::Cwe289,
            "290" => Self::Cwe290,
            "291" => Self::Cwe291,
            "293" => Self::Cwe293,
            "294" => Self::Cwe294,
            "295" => Self::Cwe295,
            "296" => Self::Cwe296,
            "297" => Self::Cwe297,
            "298" => Self::Cwe298,
            "299" => Self::Cwe299,
            "300" => Self::Cwe300,
            "301" => Self::Cwe301,
            "302" => Self::Cwe302,
            "303" => Self::Cwe303,
            "304" => Self::Cwe304,
            "305" => Self::Cwe305,
            "306" => Self::Cwe306,
            "307" => Self::Cwe307,
            "308" => Self::Cwe308,
            "309" => Self::Cwe309,
            "311" => Self::Cwe311,
            "312" => Self::Cwe312,
            "313" => Self::Cwe313,
            "314" => Self::Cwe314,
            "315" => Self::Cwe315,
            "316" => Self::Cwe316,
            "317" => Self::Cwe317,
            "318" => Self::Cwe318,
            "319" => Self::Cwe319,
            "321" => Self::Cwe321,
            "322" => Self::Cwe322,
            "323" => Self::Cwe323,
            "324" => Self::Cwe324,
            "325" => Self::Cwe325,
            "326" => Self::Cwe326,
            "327" => Self::Cwe327,
            "328" => Self::Cwe328,
            "329" => Self::Cwe329,
            "330" => Self::Cwe330,
            "331" => Self::Cwe331,
            "332" => Self::Cwe332,
            "333" => Self::Cwe333,
            "334" => Self::Cwe334,
            "335" => Self::Cwe335,
            "336" => Self::Cwe336,
            "337" => Self::Cwe337,
            "338" => Self::Cwe338,
            "339" => Self::Cwe339,
            "340" => Self::Cwe340,
            "341" => Self::Cwe341,
            "342" => Self::Cwe342,
            "343" => Self::Cwe343,
            "344" => Self::Cwe344,
            "345" => Self::Cwe345,
            "346" => Self::Cwe346,
            "347" => Self::Cwe347,
            "348" => Self::Cwe348,
            "349" => Self::Cwe349,
            "350" => Self::Cwe350,
            "351" => Self::Cwe351,
            "352" => Self::Cwe352,
            "353" => Self::Cwe353,
            "354" => Self::Cwe354,
            "356" => Self::Cwe356,
            "357" => Self::Cwe357,
            "358" => Self::Cwe358,
            "359" => Self::Cwe359,
            "360" => Self::Cwe360,
            "362" => Self::Cwe362,
            "363" => Self::Cwe363,
            "364" => Self::Cwe364,
            "366" => Self::Cwe366,
            "367" => Self::Cwe367,
            "368" => Self::Cwe368,
            "369" => Self::Cwe369,
            "370" => Self::Cwe370,
            "372" => Self::Cwe372,
            "374" => Self::Cwe374,
            "375" => Self::Cwe375,
            "377" => Self::Cwe377,
            "378" => Self::Cwe378,
            "379" => Self::Cwe379,
            "382" => Self::Cwe382,
            "383" => Self::Cwe383,
            "384" => Self::Cwe384,
            "385" => Self::Cwe385,
            "386" => Self::Cwe386,
            "390" => Self::Cwe390,
            "391" => Self::Cwe391,
            "392" => Self::Cwe392,
            "393" => Self::Cwe393,
            "394" => Self::Cwe394,
            "395" => Self::Cwe395,
            "396" => Self::Cwe396,
            "397" => Self::Cwe397,
            "400" => Self::Cwe400,
            "401" => Self::Cwe401,
            "402" => Self::Cwe402,
            "403" => Self::Cwe403,
            "404" => Self::Cwe404,
            "405" => Self::Cwe405,
            "406" => Self::Cwe406,
            "407" => Self::Cwe407,
            "408" => Self::Cwe408,
            "409" => Self::Cwe409,
            "410" => Self::Cwe410,
            "412" => Self::Cwe412,
            "413" => Self::Cwe413,
            "414" => Self::Cwe414,
            "415" => Self::Cwe415,
            "416" => Self::Cwe416,
            "419" => Self::Cwe419,
            "420" => Self::Cwe420,
            "421" => Self::Cwe421,
            "422" => Self::Cwe422,
            "424" => Self::Cwe424,
            "425" => Self::Cwe425,
            "426" => Self::Cwe426,
            "427" => Self::Cwe427,
            "428" => Self::Cwe428,
            "430" => Self::Cwe430,
            "431" => Self::Cwe431,
            "432" => Self::Cwe432,
            "433" => Self::Cwe433,
            "434" => Self::Cwe434,
            "435" => Self::Cwe435,
            "436" => Self::Cwe436,
            "437" => Self::Cwe437,
            "439" => Self::Cwe439,
            "440" => Self::Cwe440,
            "441" => Self::Cwe441,
            "444" => Self::Cwe444,
            "446" => Self::Cwe446,
            "447" => Self::Cwe447,
            "448" => Self::Cwe448,
            "449" => Self::Cwe449,
            "450" => Self::Cwe450,
            "451" => Self::Cwe451,
            "453" => Self::Cwe453,
            "454" => Self::Cwe454,
            "455" => Self::Cwe455,
            "456" => Self::Cwe456,
            "457" => Self::Cwe457,
            "459" => Self::Cwe459,
            "460" => Self::Cwe460,
            "462" => Self::Cwe462,
            "463" => Self::Cwe463,
            "464" => Self::Cwe464,
            "466" => Self::Cwe466,
            "467" => Self::Cwe467,
            "468" => Self::Cwe468,
            "469" => Self::Cwe469,
            "470" => Self::Cwe470,
            "471" => Self::Cwe471,
            "472" => Self::Cwe472,
            "473" => Self::Cwe473,
            "474" => Self::Cwe474,
            "475" => Self::Cwe475,
            "476" => Self::Cwe476,
            "477" => Self::Cwe477,
            "478" => Self::Cwe478,
            "479" => Self::Cwe479,
            "480" => Self::Cwe480,
            "481" => Self::Cwe481,
            "482" => Self::Cwe482,
            "483" => Self::Cwe483,
            "484" => Self::Cwe484,
            "486" => Self::Cwe486,
            "487" => Self::Cwe487,
            "488" => Self::Cwe488,
            "489" => Self::Cwe489,
            "491" => Self::Cwe491,
            "492" => Self::Cwe492,
            "493" => Self::Cwe493,
            "494" => Self::Cwe494,
            "495" => Self::Cwe495,
            "496" => Self::Cwe496,
            "497" => Self::Cwe497,
            "498" => Self::Cwe498,
            "499" => Self::Cwe499,
            "500" => Self::Cwe500,
            "501" => Self::Cwe501,
            "502" => Self::Cwe502,
            "506" => Self::Cwe506,
            "507" => Self::Cwe507,
            "508" => Self::Cwe508,
            "509" => Self::Cwe509,
            "510" => Self::Cwe510,
            "511" => Self::Cwe511,
            "512" => Self::Cwe512,
            "514" => Self::Cwe514,
            "515" => Self::Cwe515,
            "520" => Self::Cwe520,
            "521" => Self::Cwe521,
            "522" => Self::Cwe522,
            "523" => Self::Cwe523,
            "524" => Self::Cwe524,
            "525" => Self::Cwe525,
            "526" => Self::Cwe526,
            "527" => Self::Cwe527,
            "528" => Self::Cwe528,
            "529" => Self::Cwe529,
            "530" => Self::Cwe530,
            "531" => Self::Cwe531,
            "532" => Self::Cwe532,
            "535" => Self::Cwe535,
            "536" => Self::Cwe536,
            "537" => Self::Cwe537,
            "538" => Self::Cwe538,
            "539" => Self::Cwe539,
            "540" => Self::Cwe540,
            "541" => Self::Cwe541,
            "543" => Self::Cwe543,
            "544" => Self::Cwe544,
            "546" => Self::Cwe546,
            "547" => Self::Cwe547,
            "548" => Self::Cwe548,
            "549" => Self::Cwe549,
            "550" => Self::Cwe550,
            "551" => Self::Cwe551,
            "552" => Self::Cwe552,
            "553" => Self::Cwe553,
            "554" => Self::Cwe554,
            "555" => Self::Cwe555,
            "556" => Self::Cwe556,
            "558" => Self::Cwe558,
            "560" => Self::Cwe560,
            "561" => Self::Cwe561,
            "562" => Self::Cwe562,
            "563" => Self::Cwe563,
            "564" => Self::Cwe564,
            "565" => Self::Cwe565,
            "566" => Self::Cwe566,
            "567" => Self::Cwe567,
            "568" => Self::Cwe568,
            "570" => Self::Cwe570,
            "571" => Self::Cwe571,
            "572" => Self::Cwe572,
            "573" => Self::Cwe573,
            "574" => Self::Cwe574,
            "575" => Self::Cwe575,
            "576" => Self::Cwe576,
            "577" => Self::Cwe577,
            "578" => Self::Cwe578,
            "579" => Self::Cwe579,
            "580" => Self::Cwe580,
            "581" => Self::Cwe581,
            "582" => Self::Cwe582,
            "583" => Self::Cwe583,
            "584" => Self::Cwe584,
            "585" => Self::Cwe585,
            "586" => Self::Cwe586,
            "587" => Self::Cwe587,
            "588" => Self::Cwe588,
            "589" => Self::Cwe589,
            "590" => Self::Cwe590,
            "591" => Self::Cwe591,
            "593" => Self::Cwe593,
            "594" => Self::Cwe594,
            "595" => Self::Cwe595,
            "597" => Self::Cwe597,
            "598" => Self::Cwe598,
            "599" => Self::Cwe599,
            "600" => Self::Cwe600,
            "601" => Self::Cwe601,
            "602" => Self::Cwe602,
            "603" => Self::Cwe603,
            "605" => Self::Cwe605,
            "606" => Self::Cwe606,
            "607" => Self::Cwe607,
            "608" => Self::Cwe608,
            "609" => Self::Cwe609,
            "610" => Self::Cwe610,
            "611" => Self::Cwe611,
            "612" => Self::Cwe612,
            "613" => Self::Cwe613,
            "614" => Self::Cwe614,
            "615" => Self::Cwe615,
            "616" => Self::Cwe616,
            "617" => Self::Cwe617,
            "618" => Self::Cwe618,
            "619" => Self::Cwe619,
            "620" => Self::Cwe620,
            "621" => Self::Cwe621,
            "622" => Self::Cwe622,
            "623" => Self::Cwe623,
            "624" => Self::Cwe624,
            "625" => Self::Cwe625,
            "626" => Self::Cwe626,
            "627" => Self::Cwe627,
            "628" => Self::Cwe628,
            "636" => Self::Cwe636,
            "637" => Self::Cwe637,
            "638" => Self::Cwe638,
            "639" => Self::Cwe639,
            "640" => Self::Cwe640,
            "641" => Self::Cwe641,
            "642" => Self::Cwe642,
            "643" => Self::Cwe643,
            "644" => Self::Cwe644,
            "645" => Self::Cwe645,
            "646" => Self::Cwe646,
            "647" => Self::Cwe647,
            "648" => Self::Cwe648,
            "649" => Self::Cwe649,
            "650" => Self::Cwe650,
            "651" => Self::Cwe651,
            "652" => Self::Cwe652,
            "653" => Self::Cwe653,
            "654" => Self::Cwe654,
            "655" => Self::Cwe655,
            "656" => Self::Cwe656,
            "657" => Self::Cwe657,
            "662" => Self::Cwe662,
            "663" => Self::Cwe663,
            "664" => Self::Cwe664,
            "665" => Self::Cwe665,
            "666" => Self::Cwe666,
            "667" => Self::Cwe667,
            "668" => Self::Cwe668,
            "669" => Self::Cwe669,
            "670" => Self::Cwe670,
            "671" => Self::Cwe671,
            "672" => Self::Cwe672,
            "673" => Self::Cwe673,
            "674" => Self::Cwe674,
            "675" => Self::Cwe675,
            "676" => Self::Cwe676,
            "680" => Self::Cwe680,
            "681" => Self::Cwe681,
            "682" => Self::Cwe682,
            "683" => Self::Cwe683,
            "684" => Self::Cwe684,
            "685" => Self::Cwe685,
            "686" => Self::Cwe686,
            "687" => Self::Cwe687,
            "688" => Self::Cwe688,
            "689" => Self::Cwe689,
            "690" => Self::Cwe690,
            "691" => Self::Cwe691,
            "692" => Self::Cwe692,
            "693" => Self::Cwe693,
            "694" => Self::Cwe694,
            "695" => Self::Cwe695,
            "696" => Self::Cwe696,
            "697" => Self::Cwe697,
            "698" => Self::Cwe698,
            "703" => Self::Cwe703,
            "704" => Self::Cwe704,
            "705" => Self::Cwe705,
            "706" => Self::Cwe706,
            "707" => Self::Cwe707,
            "708" => Self::Cwe708,
            "710" => Self::Cwe710,
            "732" => Self::Cwe732,
            "733" => Self::Cwe733,
            "749" => Self::Cwe749,
            "754" => Self::Cwe754,
            "755" => Self::Cwe755,
            "756" => Self::Cwe756,
            "757" => Self::Cwe757,
            "758" => Self::Cwe758,
            "759" => Self::Cwe759,
            "760" => Self::Cwe760,
            "761" => Self::Cwe761,
            "762" => Self::Cwe762,
            "763" => Self::Cwe763,
            "764" => Self::Cwe764,
            "765" => Self::Cwe765,
            "766" => Self::Cwe766,
            "767" => Self::Cwe767,
            "768" => Self::Cwe768,
            "770" => Self::Cwe770,
            "771" => Self::Cwe771,
            "772" => Self::Cwe772,
            "773" => Self::Cwe773,
            "774" => Self::Cwe774,
            "775" => Self::Cwe775,
            "776" => Self::Cwe776,
            "777" => Self::Cwe777,
            "778" => Self::Cwe778,
            "779" => Self::Cwe779,
            "780" => Self::Cwe780,
            "781" => Self::Cwe781,
            "782" => Self::Cwe782,
            "783" => Self::Cwe783,
            "784" => Self::Cwe784,
            "785" => Self::Cwe785,
            "786" => Self::Cwe786,
            "787" => Self::Cwe787,
            "788" => Self::Cwe788,
            "789" => Self::Cwe789,
            "790" => Self::Cwe790,
            "791" => Self::Cwe791,
            "792" => Self::Cwe792,
            "793" => Self::Cwe793,
            "794" => Self::Cwe794,
            "795" => Self::Cwe795,
            "796" => Self::Cwe796,
            "797" => Self::Cwe797,
            "798" => Self::Cwe798,
            "799" => Self::Cwe799,
            "804" => Self::Cwe804,
            "805" => Self::Cwe805,
            "806" => Self::Cwe806,
            "807" => Self::Cwe807,
            "820" => Self::Cwe820,
            "821" => Self::Cwe821,
            "822" => Self::Cwe822,
            "823" => Self::Cwe823,
            "824" => Self::Cwe824,
            "825" => Self::Cwe825,
            "826" => Self::Cwe826,
            "827" => Self::Cwe827,
            "828" => Self::Cwe828,
            "829" => Self::Cwe829,
            "830" => Self::Cwe830,
            "831" => Self::Cwe831,
            "832" => Self::Cwe832,
            "833" => Self::Cwe833,
            "834" => Self::Cwe834,
            "835" => Self::Cwe835,
            "836" => Self::Cwe836,
            "837" => Self::Cwe837,
            "838" => Self::Cwe838,
            "839" => Self::Cwe839,
            "841" => Self::Cwe841,
            "842" => Self::Cwe842,
            "843" => Self::Cwe843,
            "862" => Self::Cwe862,
            "863" => Self::Cwe863,
            "908" => Self::Cwe908,
            "909" => Self::Cwe909,
            "910" => Self::Cwe910,
            "911" => Self::Cwe911,
            "912" => Self::Cwe912,
            "913" => Self::Cwe913,
            "914" => Self::Cwe914,
            "915" => Self::Cwe915,
            "916" => Self::Cwe916,
            "917" => Self::Cwe917,
            "918" => Self::Cwe918,
            "920" => Self::Cwe920,
            "921" => Self::Cwe921,
            "922" => Self::Cwe922,
            "923" => Self::Cwe923,
            "924" => Self::Cwe924,
            "925" => Self::Cwe925,
            "926" => Self::Cwe926,
            "927" => Self::Cwe927,
            "939" => Self::Cwe939,
            "940" => Self::Cwe940,
            "941" => Self::Cwe941,
            "942" => Self::Cwe942,
            "943" => Self::Cwe943,
            "1004" => Self::Cwe1004,
            "1007" => Self::Cwe1007,
            "1021" => Self::Cwe1021,
            "1022" => Self::Cwe1022,
            "1023" => Self::Cwe1023,
            "1024" => Self::Cwe1024,
            "1025" => Self::Cwe1025,
            "1037" => Self::Cwe1037,
            "1038" => Self::Cwe1038,
            "1039" => Self::Cwe1039,
            "1041" => Self::Cwe1041,
            "1042" => Self::Cwe1042,
            "1043" => Self::Cwe1043,
            "1044" => Self::Cwe1044,
            "1045" => Self::Cwe1045,
            "1046" => Self::Cwe1046,
            "1047" => Self::Cwe1047,
            "1048" => Self::Cwe1048,
            "1049" => Self::Cwe1049,
            "1050" => Self::Cwe1050,
            "1051" => Self::Cwe1051,
            "1052" => Self::Cwe1052,
            "1053" => Self::Cwe1053,
            "1054" => Self::Cwe1054,
            "1055" => Self::Cwe1055,
            "1056" => Self::Cwe1056,
            "1057" => Self::Cwe1057,
            "1058" => Self::Cwe1058,
            "1059" => Self::Cwe1059,
            "1060" => Self::Cwe1060,
            "1061" => Self::Cwe1061,
            "1062" => Self::Cwe1062,
            "1063" => Self::Cwe1063,
            "1064" => Self::Cwe1064,
            "1065" => Self::Cwe1065,
            "1066" => Self::Cwe1066,
            "1067" => Self::Cwe1067,
            "1068" => Self::Cwe1068,
            "1069" => Self::Cwe1069,
            "1070" => Self::Cwe1070,
            "1071" => Self::Cwe1071,
            "1072" => Self::Cwe1072,
            "1073" => Self::Cwe1073,
            "1074" => Self::Cwe1074,
            "1075" => Self::Cwe1075,
            "1076" => Self::Cwe1076,
            "1077" => Self::Cwe1077,
            "1078" => Self::Cwe1078,
            "1079" => Self::Cwe1079,
            "1080" => Self::Cwe1080,
            "1082" => Self::Cwe1082,
            "1083" => Self::Cwe1083,
            "1084" => Self::Cwe1084,
            "1085" => Self::Cwe1085,
            "1086" => Self::Cwe1086,
            "1087" => Self::Cwe1087,
            "1088" => Self::Cwe1088,
            "1089" => Self::Cwe1089,
            "1090" => Self::Cwe1090,
            "1091" => Self::Cwe1091,
            "1092" => Self::Cwe1092,
            "1093" => Self::Cwe1093,
            "1094" => Self::Cwe1094,
            "1095" => Self::Cwe1095,
            "1096" => Self::Cwe1096,
            "1097" => Self::Cwe1097,
            "1098" => Self::Cwe1098,
            "1099" => Self::Cwe1099,
            "1100" => Self::Cwe1100,
            "1101" => Self::Cwe1101,
            "1102" => Self::Cwe1102,
            "1103" => Self::Cwe1103,
            "1104" => Self::Cwe1104,
            "1105" => Self::Cwe1105,
            "1106" => Self::Cwe1106,
            "1107" => Self::Cwe1107,
            "1108" => Self::Cwe1108,
            "1109" => Self::Cwe1109,
            "1110" => Self::Cwe1110,
            "1111" => Self::Cwe1111,
            "1112" => Self::Cwe1112,
            "1113" => Self::Cwe1113,
            "1114" => Self::Cwe1114,
            "1115" => Self::Cwe1115,
            "1116" => Self::Cwe1116,
            "1117" => Self::Cwe1117,
            "1118" => Self::Cwe1118,
            "1119" => Self::Cwe1119,
            "1120" => Self::Cwe1120,
            "1121" => Self::Cwe1121,
            "1122" => Self::Cwe1122,
            "1123" => Self::Cwe1123,
            "1124" => Self::Cwe1124,
            "1125" => Self::Cwe1125,
            "1126" => Self::Cwe1126,
            "1127" => Self::Cwe1127,
            "1164" => Self::Cwe1164,
            "1173" => Self::Cwe1173,
            "1174" => Self::Cwe1174,
            "1176" => Self::Cwe1176,
            "1177" => Self::Cwe1177,
            "1188" => Self::Cwe1188,
            "1189" => Self::Cwe1189,
            "1190" => Self::Cwe1190,
            "1191" => Self::Cwe1191,
            "1192" => Self::Cwe1192,
            "1193" => Self::Cwe1193,
            "1204" => Self::Cwe1204,
            "1209" => Self::Cwe1209,
            "1220" => Self::Cwe1220,
            "1221" => Self::Cwe1221,
            "1222" => Self::Cwe1222,
            "1223" => Self::Cwe1223,
            "1224" => Self::Cwe1224,
            "1229" => Self::Cwe1229,
            "1230" => Self::Cwe1230,
            "1231" => Self::Cwe1231,
            "1232" => Self::Cwe1232,
            "1233" => Self::Cwe1233,
            "1234" => Self::Cwe1234,
            "1235" => Self::Cwe1235,
            "1236" => Self::Cwe1236,
            "1239" => Self::Cwe1239,
            "1240" => Self::Cwe1240,
            "1241" => Self::Cwe1241,
            "1242" => Self::Cwe1242,
            "1243" => Self::Cwe1243,
            "1244" => Self::Cwe1244,
            "1245" => Self::Cwe1245,
            "1246" => Self::Cwe1246,
            "1247" => Self::Cwe1247,
            "1248" => Self::Cwe1248,
            "1249" => Self::Cwe1249,
            "1250" => Self::Cwe1250,
            "1251" => Self::Cwe1251,
            "1252" => Self::Cwe1252,
            "1253" => Self::Cwe1253,
            "1254" => Self::Cwe1254,
            "1255" => Self::Cwe1255,
            "1256" => Self::Cwe1256,
            "1257" => Self::Cwe1257,
            "1258" => Self::Cwe1258,
            "1259" => Self::Cwe1259,
            "1260" => Self::Cwe1260,
            "1261" => Self::Cwe1261,
            "1262" => Self::Cwe1262,
            "1263" => Self::Cwe1263,
            "1264" => Self::Cwe1264,
            "1265" => Self::Cwe1265,
            "1266" => Self::Cwe1266,
            "1267" => Self::Cwe1267,
            "1268" => Self::Cwe1268,
            "1269" => Self::Cwe1269,
            "1270" => Self::Cwe1270,
            "1271" => Self::Cwe1271,
            "1272" => Self::Cwe1272,
            "1273" => Self::Cwe1273,
            "1274" => Self::Cwe1274,
            "1275" => Self::Cwe1275,
            "1276" => Self::Cwe1276,
            "1277" => Self::Cwe1277,
            "1278" => Self::Cwe1278,
            "1279" => Self::Cwe1279,
            "1280" => Self::Cwe1280,
            "1281" => Self::Cwe1281,
            "1282" => Self::Cwe1282,
            "1283" => Self::Cwe1283,
            "1284" => Self::Cwe1284,
            "1285" => Self::Cwe1285,
            "1286" => Self::Cwe1286,
            "1287" => Self::Cwe1287,
            "1288" => Self::Cwe1288,
            "1289" => Self::Cwe1289,
            "1290" => Self::Cwe1290,
            "1291" => Self::Cwe1291,
            "1292" => Self::Cwe1292,
            "1293" => Self::Cwe1293,
            "1294" => Self::Cwe1294,
            "1295" => Self::Cwe1295,
            "1296" => Self::Cwe1296,
            "1297" => Self::Cwe1297,
            "1298" => Self::Cwe1298,
            "1299" => Self::Cwe1299,
            "1300" => Self::Cwe1300,
            "1301" => Self::Cwe1301,
            "1302" => Self::Cwe1302,
            "1303" => Self::Cwe1303,
            "1304" => Self::Cwe1304,
            "1310" => Self::Cwe1310,
            "1311" => Self::Cwe1311,
            "1312" => Self::Cwe1312,
            "1313" => Self::Cwe1313,
            "1314" => Self::Cwe1314,
            "1315" => Self::Cwe1315,
            "1316" => Self::Cwe1316,
            "1317" => Self::Cwe1317,
            "1318" => Self::Cwe1318,
            "1319" => Self::Cwe1319,
            "1320" => Self::Cwe1320,
            "1321" => Self::Cwe1321,
            "1322" => Self::Cwe1322,
            "1323" => Self::Cwe1323,
            "1325" => Self::Cwe1325,
            "1326" => Self::Cwe1326,
            "1327" => Self::Cwe1327,
            "1328" => Self::Cwe1328,
            "1329" => Self::Cwe1329,
            "1330" => Self::Cwe1330,
            "1331" => Self::Cwe1331,
            "1332" => Self::Cwe1332,
            "1333" => Self::Cwe1333,
            "1334" => Self::Cwe1334,
            "1335" => Self::Cwe1335,
            "1336" => Self::Cwe1336,
            "1338" => Self::Cwe1338,
            "1339" => Self::Cwe1339,
            "1341" => Self::Cwe1341,
            "1342" => Self::Cwe1342,
            "1351" => Self::Cwe1351,
            "1357" => Self::Cwe1357,
            "1384" => Self::Cwe1384,
            "1385" => Self::Cwe1385,
            "1386" => Self::Cwe1386,
            "1389" => Self::Cwe1389,
            "1390" => Self::Cwe1390,
            "1391" => Self::Cwe1391,
            "1392" => Self::Cwe1392,
            "1393" => Self::Cwe1393,
            "1394" => Self::Cwe1394,
            "1395" => Self::Cwe1395,
            "1419" => Self::Cwe1419,
            _ => return Err(CWEParseError),
        };

        Ok(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_deserialise() -> Result<(), Box<dyn std::error::Error>> {
        let cwe = "\"CWE-1334\"";
        let bad_cwe = "\"CWE-1337\"";

        assert!(matches!(serde_json::from_str(cwe), Ok(CWE::Cwe1334)));
        assert!(matches!(serde_json::from_str::<CWE>(bad_cwe), Err(_)));

        Ok(())
    }

    #[test]
    fn test_parse() -> Result<(), Box<dyn std::error::Error>> {
        let cwe = "CWE-1334";
        let bad_cwe = "CWE-1337";

        assert!(matches!(cwe.parse(), Ok(CWE::Cwe1334)));
        assert!(matches!(bad_cwe.parse::<CWE>(), Err(_)));

        Ok(())
    }
}
