package org.csploit.android.net.metasploit;

import org.csploit.android.core.Logger;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

/**
 * this class store data about MSF options.
 * options can be about both exploits and payload.
 */
@SuppressWarnings("unchecked")
public class Option {
  private final static String[] requiredFields = new String[] {"type","required","advanced","evasion","desc"};
  private final static Map<String,types> typesMap = new java.util.HashMap<String, types>() {
    {
      put("string", types.STRING);
      put("bool", types.BOOLEAN);
      put("address", types.ADDRESS);
      put("integer", types.INTEGER);
      put("port", types.PORT);
      put("path", types.PATH);
      put("enum", types.ENUM);
    }
  };

  public enum types {
    STRING,
    BOOLEAN,
    PATH,
    ADDRESS,
    INTEGER,
    PORT,
    ENUM
  }

  private String mName,mDesc,mValue;
  private Map<String,Object> mAttributes;
  private types mType;
  private boolean mAdvanced,mRequired,mEvasion;
  private String[] enums;

  public Option(String name, Map<String,Object> attrs) throws IllegalArgumentException {
    mName = name;
    mAttributes = attrs;
    // check for required data
    for(String field : requiredFields)
      if(!mAttributes.containsKey(field))
        throw new IllegalArgumentException("missing "+field+" field");
    // get type
    String type = (String) mAttributes.get("type");
    if(!typesMap.containsKey(type))
      throw new IllegalArgumentException("unknown option type: "+type);
    mType = typesMap.get(type);
    if(mType == types.ENUM) {
      if(!mAttributes.containsKey("enums"))
        throw new IllegalArgumentException("missing enums field");
      // TODO: ENHANCEMENT - Search if exists non-string enums
      // PROBLEM: Assumes all enum values are strings, but Metasploit may send
      // enum options with integer values (for bitmask options, exit codes, etc.)
      // CURRENT WORKAROUND: Cast all enums to String, throws exception for non-ArrayList
      // SOLUTION: Support both String and Integer enum types:
      // - Check type of enum values at runtime
      // - Convert integers to string representation for display
      // - Handle validation with type-aware comparison
      // IMPACT: Low - Only affects advanced options with integer enums
      Object enumsObj = mAttributes.get("enums");
      if(enumsObj instanceof ArrayList) {
        ArrayList enumsList = (ArrayList) enumsObj;
        enums = new String[enumsList.size()];
        for(int i = 0; i < enumsList.size(); i++) {
          Object val = enumsList.get(i);
          enums[i] = val instanceof String ? (String)val : String.valueOf(val);
        }
      } else {
        throw new IllegalArgumentException("enums field must be an ArrayList");
      }
    }
    // get all other data
    mDesc = (String) mAttributes.get("desc");
    mAdvanced = (Boolean) mAttributes.get("advanced");
    mRequired = (Boolean) mAttributes.get("required");
    mEvasion  = (Boolean) mAttributes.get("evasion");
  }


  public String getName() {
    return mName;
  }

  public String getDescription() {
    return mDesc;
  }

  public types getType() {
    return mType;
  }

  public boolean isAdvanced() {
    return mAdvanced;
  }

  public boolean isRequired() {
    return mRequired;
  }

  public boolean isEvasion() {
    return mEvasion;
  }

  public String[] getEnum() {
    return Arrays.copyOf(enums, enums.length);
  }

  // TODO: ENHANCEMENT - Make more setValue methods with corresponding types
  // PROBLEM: Current implementation only has setValue(String), requiring all callers to
  // convert values to strings first. This is error-prone and loses type safety.
  // CURRENT WORKAROUND: Single string-based setValue with type conversion inside.
  // SOLUTION: Add type-specific setValue overloads:
  // - setValue(int) for PORT, INTEGER types
  // - setValue(InetAddress) for ADDRESS type
  // - setValue(boolean) for BOOLEAN type
  // - setValue(Path) for PATH type
  // BENEFITS:
  // - Type safety at compile time
  // - Clearer caller intent
  // - Reduced string parsing/conversion
  // IMPACT: Low - Enhancement for better API design
  public void setValue(String value) throws NumberFormatException {
    switch (mType) {
      case STRING:
        mValue = value;
        break;
      case ADDRESS:
        try {
          mValue = InetAddress.getByName(value).getHostAddress();
        } catch (UnknownHostException uhe) {
          throw new NumberFormatException("invalid IP address: " + value);
        }
        break;
      case PORT:
        int i = Integer.parseInt(value);
        if(i<0 || i > 65535)
          throw new NumberFormatException("port must be between 0 and 65535");
        break;
      case BOOLEAN:
        value=value.toLowerCase();
        if(value.equals("true") || value.equals("false"))
          mValue=value;
        else
          throw new NumberFormatException("boolean must be true or false");
        break;
      case ENUM:
        // TODO: ENHANCEMENT - Handle integer enums in addition to string enums
        // PROBLEM: ENUM validation assumes all enum values are strings, but Metasploit
        // may send options with integer enum values (exit codes, flags, etc.)
        // CURRENT WORKAROUND: String comparison only; integer enums cause validation failure
        // SOLUTION: Support both string and integer enum validation:
        // - Get enums from mAttributes (may contain mixed types)
        // - Check if provided value matches as string OR as integer
        // - Log better error messages showing both types
        ArrayList valid = ((ArrayList)mAttributes.get("enums"));
        boolean found = false;
        for(Object v : valid) {
          if(v instanceof String && ((String)v).equals(value)) {
            found = true;
            break;
          } else if(v instanceof Integer && String.valueOf(v).equals(value)) {
            found = true;
            break;
          }
        }
        if(!found) {
          final StringBuilder validLineBuilder = new StringBuilder();
          for(Object v : valid) {
            validLineBuilder.append(" ").append(v);
          }
          Logger.warning("expected: (" + validLineBuilder.toString() + ") got: " + value);
          throw new NumberFormatException("invalid choice");
        }
        mValue = value;
        break;
      case PATH:
        // PATH values are accepted as-is without further validation
        // Validation occurs when the path is actually used
        mValue = value;
        break;
    }
  }

  public String getValue() {
    if(mValue!=null)
      return mValue;
    else if(mAttributes.containsKey("default"))
      return mAttributes.get("default").toString();
    else
      return "";
  }
}
