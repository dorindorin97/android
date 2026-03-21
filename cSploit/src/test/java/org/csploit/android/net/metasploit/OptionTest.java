package org.csploit.android.net.metasploit;

import org.junit.Test;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for the Option class (MSF option type validation and value storage).
 *
 * Covers the bugs fixed in:
 *  - PORT type: mValue was not set after validation
 *  - INTEGER type: missing case in setValue() switch
 *  - Typed setValue overloads: setValue(int), setValue(boolean), setValue(InetAddress)
 */
public class OptionTest {

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private Map<String, Object> baseAttrs(String type) {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("type", type);
        attrs.put("required", false);
        attrs.put("advanced", false);
        attrs.put("evasion", false);
        attrs.put("desc", "test option");
        return attrs;
    }

    private Option make(String type) {
        return new Option("OPT", baseAttrs(type));
    }

    private Option makeEnum(String... choices) {
        Map<String, Object> attrs = baseAttrs("enum");
        ArrayList<String> enums = new ArrayList<>();
        for (String c : choices) enums.add(c);
        attrs.put("enums", enums);
        return new Option("OPT", attrs);
    }

    // -------------------------------------------------------------------------
    // STRING
    // -------------------------------------------------------------------------

    @Test
    public void string_setValue_storesValue() {
        Option opt = make("string");
        opt.setValue("hello");
        assertEquals("hello", opt.getValue());
    }

    // -------------------------------------------------------------------------
    // INTEGER — regression test: was entirely missing from the switch
    // -------------------------------------------------------------------------

    @Test
    public void integer_setValue_string_storesValue() {
        Option opt = make("integer");
        opt.setValue("42");
        assertEquals("42", opt.getValue());
    }

    @Test(expected = NumberFormatException.class)
    public void integer_setValue_invalidString_throws() {
        Option opt = make("integer");
        opt.setValue("not-a-number");
    }

    @Test
    public void integer_setValue_int_storesValue() {
        Option opt = make("integer");
        opt.setValue(99);
        assertEquals("99", opt.getValue());
    }

    @Test
    public void integer_setValue_negativeInt_isAllowed() {
        Option opt = make("integer");
        opt.setValue(-1);
        assertEquals("-1", opt.getValue());
    }

    // -------------------------------------------------------------------------
    // PORT — regression test: mValue was not stored after validation
    // -------------------------------------------------------------------------

    @Test
    public void port_setValue_string_storesValue() {
        Option opt = make("port");
        opt.setValue("8080");
        assertEquals("8080", opt.getValue());
    }

    @Test(expected = NumberFormatException.class)
    public void port_setValue_negative_throws() {
        Option opt = make("port");
        opt.setValue("-1");
    }

    @Test(expected = NumberFormatException.class)
    public void port_setValue_tooHigh_throws() {
        Option opt = make("port");
        opt.setValue("65536");
    }

    @Test
    public void port_setValue_int_storesValue() {
        Option opt = make("port");
        opt.setValue(443);
        assertEquals("443", opt.getValue());
    }

    @Test(expected = NumberFormatException.class)
    public void port_setValue_int_tooHigh_throws() {
        Option opt = make("port");
        opt.setValue(70000);
    }

    @Test
    public void port_setValue_zero_isAllowed() {
        Option opt = make("port");
        opt.setValue(0);
        assertEquals("0", opt.getValue());
    }

    @Test
    public void port_setValue_maxPort_isAllowed() {
        Option opt = make("port");
        opt.setValue(65535);
        assertEquals("65535", opt.getValue());
    }

    // -------------------------------------------------------------------------
    // BOOLEAN
    // -------------------------------------------------------------------------

    @Test
    public void boolean_setValue_true_storesValue() {
        Option opt = make("bool");
        opt.setValue("true");
        assertEquals("true", opt.getValue());
    }

    @Test
    public void boolean_setValue_false_storesValue() {
        Option opt = make("bool");
        opt.setValue("false");
        assertEquals("false", opt.getValue());
    }

    @Test(expected = NumberFormatException.class)
    public void boolean_setValue_invalid_throws() {
        Option opt = make("bool");
        opt.setValue("yes");
    }

    @Test
    public void boolean_setValue_booleanTrue_storesValue() {
        Option opt = make("bool");
        opt.setValue(true);
        assertEquals("true", opt.getValue());
    }

    @Test
    public void boolean_setValue_booleanFalse_storesValue() {
        Option opt = make("bool");
        opt.setValue(false);
        assertEquals("false", opt.getValue());
    }

    @Test(expected = NumberFormatException.class)
    public void boolean_setValue_booleanOnWrongType_throws() {
        Option opt = make("string");
        opt.setValue(true);
    }

    // -------------------------------------------------------------------------
    // ADDRESS
    // -------------------------------------------------------------------------

    @Test
    public void address_setValue_validIp_storesValue() {
        Option opt = make("address");
        opt.setValue("192.168.1.1");
        assertEquals("192.168.1.1", opt.getValue());
    }

    @Test(expected = NumberFormatException.class)
    public void address_setValue_invalidHost_throws() {
        Option opt = make("address");
        opt.setValue("not.an.ip.address.invalid.invalid.invalid");
    }

    @Test
    public void address_setValue_inetAddress_storesHostAddress() throws Exception {
        Option opt = make("address");
        InetAddress addr = InetAddress.getByName("10.0.0.1");
        opt.setValue(addr);
        assertEquals("10.0.0.1", opt.getValue());
    }

    @Test(expected = NumberFormatException.class)
    public void address_setValue_inetAddressOnWrongType_throws() throws Exception {
        Option opt = make("string");
        opt.setValue(InetAddress.getByName("10.0.0.1"));
    }

    // -------------------------------------------------------------------------
    // ENUM
    // -------------------------------------------------------------------------

    @Test
    public void enum_setValue_validChoice_storesValue() {
        Option opt = makeEnum("tcp", "udp", "icmp");
        opt.setValue("udp");
        assertEquals("udp", opt.getValue());
    }

    @Test(expected = NumberFormatException.class)
    public void enum_setValue_invalidChoice_throws() {
        Option opt = makeEnum("tcp", "udp");
        opt.setValue("sctp");
    }

    @Test
    public void enum_integerEnumValues_matchByStringRepresentation() {
        Map<String, Object> attrs = baseAttrs("enum");
        ArrayList<Object> enums = new ArrayList<>();
        enums.add(1);
        enums.add(2);
        enums.add(3);
        attrs.put("enums", enums);
        Option opt = new Option("OPT", attrs);
        opt.setValue("2");
        assertEquals("2", opt.getValue());
    }

    // -------------------------------------------------------------------------
    // PATH
    // -------------------------------------------------------------------------

    @Test
    public void path_setValue_storesValue() {
        Option opt = make("path");
        opt.setValue("/tmp/test.txt");
        assertEquals("/tmp/test.txt", opt.getValue());
    }

    // -------------------------------------------------------------------------
    // Default value fallback
    // -------------------------------------------------------------------------

    @Test
    public void getValue_withDefault_returnsDefaultWhenNoValueSet() {
        Map<String, Object> attrs = baseAttrs("string");
        attrs.put("default", "defaultVal");
        Option opt = new Option("OPT", attrs);
        assertEquals("defaultVal", opt.getValue());
    }

    @Test
    public void getValue_noDefaultNoValue_returnsEmptyString() {
        Option opt = make("string");
        assertEquals("", opt.getValue());
    }

    // -------------------------------------------------------------------------
    // Constructor validation
    // -------------------------------------------------------------------------

    @Test(expected = IllegalArgumentException.class)
    public void constructor_missingRequiredField_throws() {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("type", "string");
        // missing required, advanced, evasion, desc
        new Option("OPT", attrs);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructor_unknownType_throws() {
        Map<String, Object> attrs = baseAttrs("unknowntype");
        new Option("OPT", attrs);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructor_enumMissingEnumsList_throws() {
        Map<String, Object> attrs = baseAttrs("enum");
        // no "enums" key
        new Option("OPT", attrs);
    }
}
