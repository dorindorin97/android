package org.csploit.android.plugins;

import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import org.csploit.android.R;
import org.csploit.android.core.Plugin;
import org.csploit.android.net.Target;

import java.util.ArrayList;
import java.util.List;

/**
 * Hash Identifier — identifies common hash types by length, character set,
 * and known prefix patterns.  Updates in real-time as the user types.
 *
 * Shows: hash type, hashcat mode (-m), john format, and notes.
 * Works offline — no network needed.
 */
public class HashIdentifier extends Plugin {

    public static class HashType {
        public enum Confidence { LIKELY, POSSIBLE }
        public final Confidence confidence;
        public final String name;
        public final String hashcatMode;
        public final String johnFormat;
        public final String notes;
        HashType(Confidence c, String n, String hm, String jf, String notes) {
            confidence = c; name = n; hashcatMode = hm; johnFormat = jf; this.notes = notes;
        }
    }

    private EditText mHashInput;
    private ListView mListView;
    private TypeAdapter mAdapter;

    public HashIdentifier() {
        super(
            R.string.hash_identifier,
            R.string.hash_identifier_desc,
            new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE, Target.Type.NETWORK},
            R.layout.plugin_hash_identifier,
            R.drawable.action_exploit_finder
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mHashInput = findViewById(R.id.hashInput);
        mListView  = findViewById(android.R.id.list);
        mAdapter   = new TypeAdapter();
        mListView.setAdapter(mAdapter);

        mHashInput.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) {}
            public void onTextChanged(CharSequence s, int st, int b, int c) {}
            public void afterTextChanged(Editable s) { identify(s.toString().trim()); }
        });

        // Show example on start
        identify("");
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // ── Identification logic ──────────────────────────────────────────────────

    private void identify(String hash) {
        mAdapter.clear();
        if (hash.isEmpty()) {
            mAdapter.add(new HashType(HashType.Confidence.LIKELY, "Paste a hash above", "", "", "Identification updates in real-time"));
            mAdapter.notifyDataSetChanged();
            return;
        }

        List<HashType> results = new ArrayList<>();

        // Prefix-based (most reliable)
        if (hash.startsWith("$2y$") || hash.startsWith("$2a$") || hash.startsWith("$2b$"))
            results.add(new HashType(HashType.Confidence.LIKELY, "bcrypt", "3200", "bcrypt", "Cost factor embedded in hash"));
        else if (hash.startsWith("$1$"))
            results.add(new HashType(HashType.Confidence.LIKELY, "MD5-crypt (Unix)", "500", "md5crypt", "Used in old Linux /etc/shadow"));
        else if (hash.startsWith("$5$"))
            results.add(new HashType(HashType.Confidence.LIKELY, "SHA-256-crypt (Unix)", "7400", "sha256crypt", "Linux /etc/shadow"));
        else if (hash.startsWith("$6$"))
            results.add(new HashType(HashType.Confidence.LIKELY, "SHA-512-crypt (Unix)", "1800", "sha512crypt", "Linux /etc/shadow (default)"));
        else if (hash.startsWith("$P$") || hash.startsWith("$H$"))
            results.add(new HashType(HashType.Confidence.LIKELY, "WordPress / phpBB MD5", "400", "phpass", "Portable PHP password hash"));
        else if (hash.startsWith("$apr1$"))
            results.add(new HashType(HashType.Confidence.LIKELY, "Apache MD5-APR1", "1600", "md5apr1", "Apache .htpasswd"));
        else if (hash.startsWith("{SHA}"))
            results.add(new HashType(HashType.Confidence.LIKELY, "SHA-1 (Base64, LDAP)", "101", "raw-sha1", "LDAP userPassword"));
        else if (hash.startsWith("sha1$"))
            results.add(new HashType(HashType.Confidence.LIKELY, "Django SHA-1", "124", "", "Django legacy format"));
        else if (hash.startsWith("pbkdf2_sha256$"))
            results.add(new HashType(HashType.Confidence.LIKELY, "Django PBKDF2-SHA256", "10000", "", "Django default (≥1.4)"));
        else if (hash.startsWith("0x0200"))
            results.add(new HashType(HashType.Confidence.LIKELY, "MSSQL 2000", "131", "mssql", "MS SQL Server 2000"));
        else if (hash.startsWith("0x0100"))
            results.add(new HashType(HashType.Confidence.LIKELY, "MSSQL 2005+", "132", "mssql05", "MS SQL Server 2005+"));
        else {
            // Length + charset based
            boolean isHex    = hash.matches("[0-9a-fA-F]+");
            boolean isBase64 = hash.matches("[A-Za-z0-9+/=]+");
            int len = hash.length();

            if (isHex) {
                switch (len) {
                    case 8:  results.add(lk("CRC-32",          "11500", "",          "Checksum, not a password hash")); break;
                    case 16: results.add(lk("MySQL323",         "200",  "mysql",      "MySQL < 4.1"));
                             results.add(pk("Half MD5",          "5100", "",           "First 8 bytes of MD5")); break;
                    case 32: results.add(lk("MD5",               "0",    "raw-md5",    "Most common 32-char hex hash"));
                             results.add(pk("NTLM",              "1000", "nt",         "Windows NT hash (same length as MD5)"));
                             results.add(pk("MD4",               "900",  "raw-md4",    "")); break;
                    case 40: results.add(lk("SHA-1",             "100",  "raw-sha1",   ""));
                             results.add(pk("MySQL 4.1+",        "300",  "mysql41",    "SHA1(SHA1(password))"));
                             results.add(pk("Cisco IOS type 5",  "2400", "cisco4",     "")); break;
                    case 48: results.add(lk("SHA-224 / Tiger-192","",   "",            "")); break;
                    case 56: results.add(lk("SHA-224",           "1300", "",           "")); break;
                    case 64: results.add(lk("SHA-256",           "1400", "raw-sha256", ""));
                             results.add(pk("Keccak-256",        "17300","",           "Not SHA3-256")); break;
                    case 96: results.add(lk("SHA-384",           "10800","raw-sha384", "")); break;
                    case 128:results.add(lk("SHA-512",           "1700", "raw-sha512", ""));
                             results.add(pk("Whirlpool",         "6100", "whirlpool",  "")); break;
                }
            }
            if (isBase64 && results.isEmpty()) {
                if (len == 24) results.add(pk("SHA-1 (Base64)",  "101",  "raw-sha1",   "Base64-encoded SHA-1"));
                if (len == 28) results.add(pk("SHA-224 (Base64)","",    "",            ""));
                if (len == 44) results.add(pk("SHA-256 (Base64)","1400", "raw-sha256", ""));
                if (len == 60) results.add(lk("bcrypt (truncated)", "3200","bcrypt",   "May be missing prefix"));
                if (len == 88) results.add(pk("SHA-512 (Base64)","1700", "raw-sha512", ""));
            }
            // LM hash pair (33 chars with colon) - NTLM SAM format
            if (hash.contains(":") && hash.length() == 65 && isHex(hash.replace(":", "")))
                results.add(lk("LM:NTLM (SAM dump)",  "1000", "nt", "Use -m 3000 for LM part"));

            if (results.isEmpty())
                results.add(new HashType(HashType.Confidence.POSSIBLE, "Unknown / custom format",
                    "", "", "Length: " + len + ", charset: " + (isHex ? "hex" : isBase64 ? "base64" : "other")));
        }

        for (HashType ht : results) mAdapter.add(ht);
        mAdapter.notifyDataSetChanged();
    }

    private boolean isHex(String s) { return s.matches("[0-9a-fA-F]+"); }
    private HashType lk(String n, String hm, String jf, String notes) {
        return new HashType(HashType.Confidence.LIKELY,   n, hm, jf, notes);
    }
    private HashType pk(String n, String hm, String jf, String notes) {
        return new HashType(HashType.Confidence.POSSIBLE, n, hm, jf, notes);
    }

    // ── Adapter ───────────────────────────────────────────────────────────────

    private class TypeAdapter extends ArrayAdapter<HashType> {
        TypeAdapter() { super(HashIdentifier.this, R.layout.plugin_hash_identifier_item, new ArrayList<>()); }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_hash_identifier_item, parent, false);
            HashType h = getItem(position);
            TextView tvName = convertView.findViewById(R.id.hashItemName);
            TextView tvMeta = convertView.findViewById(R.id.hashItemMeta);
            TextView tvConf = convertView.findViewById(R.id.hashItemConf);
            TextView tvNote = convertView.findViewById(R.id.hashItemNote);

            tvName.setText(h.name);

            StringBuilder meta = new StringBuilder();
            if (!h.hashcatMode.isEmpty()) meta.append("hashcat -m ").append(h.hashcatMode);
            if (!h.johnFormat.isEmpty()) {
                if (meta.length() > 0) meta.append("   ");
                meta.append("john --format=").append(h.johnFormat);
            }
            tvMeta.setText(meta.toString());
            tvNote.setText(h.notes);

            boolean likely = h.confidence == HashType.Confidence.LIKELY;
            tvConf.setText(likely ? "LIKELY" : "POSSIBLE");
            tvConf.setTextColor(likely ? Color.parseColor("#388E3C") : Color.parseColor("#F57C00"));
            tvName.setTextColor(likely
                ? ContextCompat.getColor(getContext(), R.color.app_color)
                : Color.parseColor("#757575"));

            return convertView;
        }
    }
}
