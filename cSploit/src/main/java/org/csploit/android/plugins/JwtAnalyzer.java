package org.csploit.android.plugins;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Base64;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import org.csploit.android.BuildConfig;
import org.csploit.android.R;
import org.csploit.android.core.Plugin;
import org.csploit.android.net.Target;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class JwtAnalyzer extends Plugin {

    // --------------- result model ---------------
    public static class JwtFinding {
        public enum Kind { INFO, WARN, VULN }
        public Kind kind;
        public String label;
        public String value;

        public JwtFinding(Kind kind, String label, String value) {
            this.kind = kind;
            this.label = label;
            this.value = value;
        }
    }

    // --------------- adapter ---------------
    private class JwtAdapter extends ArrayAdapter<JwtFinding> {
        JwtAdapter(List<JwtFinding> items) {
            super(JwtAnalyzer.this, R.layout.plugin_jwt_analyzer_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_jwt_analyzer_item, parent, false);
            }
            JwtFinding f = getItem(position);
            TextView labelView = convertView.findViewById(R.id.jwtItemLabel);
            TextView valueView = convertView.findViewById(R.id.jwtItemValue);
            if (f != null) {
                labelView.setText(f.label);
                valueView.setText(f.value);
                int color;
                switch (f.kind) {
                    case VULN: color = 0xFFD32F2F; break;
                    case WARN: color = 0xFFF57C00; break;
                    default:   color = ContextCompat.getColor(JwtAnalyzer.this, R.color.app_color); break;
                }
                labelView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private EditText mInput;
    private ListView mList;
    private final List<JwtFinding> mFindings = new ArrayList<>();
    private JwtAdapter mAdapter;

    // --------------- constructor ---------------
    public JwtAnalyzer() {
        super(R.string.jwt_analyzer, R.string.jwt_analyzer_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE, Target.Type.NETWORK},
                R.layout.plugin_jwt_analyzer, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mInput = findViewById(R.id.jwtInput);
        mList = findViewById(android.R.id.list);

        mAdapter = new JwtAdapter(mFindings);
        mList.setAdapter(mAdapter);

        mInput.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override
            public void afterTextChanged(Editable s) {
                String token = s.toString().trim();
                mFindings.clear();
                if (token.isEmpty()) {
                    mFindings.add(new JwtFinding(JwtFinding.Kind.INFO,
                            "Paste a JWT token above", ""));
                } else {
                    analyze(token);
                }
                mAdapter.notifyDataSetChanged();
            }
        });

        // Show initial prompt
        mFindings.add(new JwtFinding(JwtFinding.Kind.INFO, "Paste a JWT token above", ""));
        mAdapter.notifyDataSetChanged();
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // --------------- analysis ---------------
    private void analyze(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            mFindings.add(new JwtFinding(JwtFinding.Kind.WARN, "Invalid JWT format",
                    "Expected 3 parts separated by '.'"));
            return;
        }

        // Decode header
        String headerJson;
        String payloadJson;
        try {
            headerJson = new String(Base64.decode(
                    padBase64(parts[0].replace('-', '+').replace('_', '/')),
                    Base64.NO_WRAP), "UTF-8");
            payloadJson = new String(Base64.decode(
                    padBase64(parts[1].replace('-', '+').replace('_', '/')),
                    Base64.NO_WRAP), "UTF-8");
        } catch (Exception e) {
            mFindings.add(new JwtFinding(JwtFinding.Kind.WARN, "Decode error",
                    "Could not base64-decode header or payload"));
            return;
        }

        // Parse header fields
        String alg = extractJsonString(headerJson, "alg");
        String typ = extractJsonString(headerJson, "typ");
        String kid = extractJsonString(headerJson, "kid");

        if (alg != null) {
            mFindings.add(new JwtFinding(JwtFinding.Kind.INFO, "Algorithm", alg));
            String algLower = alg.toLowerCase(Locale.US);
            if (algLower.equals("none")) {
                mFindings.add(new JwtFinding(JwtFinding.Kind.VULN, "alg:none",
                        "Signature not verified — token may be forged"));
            } else if (algLower.startsWith("hs")) {
                mFindings.add(new JwtFinding(JwtFinding.Kind.WARN, "HMAC algorithm",
                        "Secret may be brute-forced offline"));
            }
        }
        if (typ != null) mFindings.add(new JwtFinding(JwtFinding.Kind.INFO, "Type", typ));
        if (kid != null) mFindings.add(new JwtFinding(JwtFinding.Kind.WARN, "kid claim",
                kid + " — verify kid injection is not possible"));

        // Parse payload fields
        String sub  = extractJsonString(payloadJson, "sub");
        String iss  = extractJsonString(payloadJson, "iss");
        String aud  = extractJsonString(payloadJson, "aud");
        String email = extractJsonString(payloadJson, "email");
        String role = extractJsonString(payloadJson, "role");
        Long   exp  = extractJsonLong(payloadJson, "exp");
        Long   iat  = extractJsonLong(payloadJson, "iat");
        String adminVal = extractJsonString(payloadJson, "admin");

        if (iss != null)  mFindings.add(new JwtFinding(JwtFinding.Kind.INFO, "Issued by", iss));
        if (sub != null)  mFindings.add(new JwtFinding(JwtFinding.Kind.INFO, "Subject", sub));
        if (aud != null)  mFindings.add(new JwtFinding(JwtFinding.Kind.INFO, "Audience", aud));

        if (iat != null) {
            mFindings.add(new JwtFinding(JwtFinding.Kind.INFO, "Issued at",
                    formatEpoch(iat)));
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
        long now = java.lang.System.currentTimeMillis() / 1000L;

        if (exp != null) {
            String expStr = formatEpoch(exp);
            if (exp < now) {
                mFindings.add(new JwtFinding(JwtFinding.Kind.VULN, "Token Expired", expStr));
            } else {
                mFindings.add(new JwtFinding(JwtFinding.Kind.INFO, "Expires", expStr));
                long tenYears = now + 10L * 365 * 24 * 3600;
                if (exp > tenYears) {
                    mFindings.add(new JwtFinding(JwtFinding.Kind.WARN, "Very long expiry",
                            "Token valid for >10 years"));
                }
            }
        }

        if ("true".equalsIgnoreCase(adminVal)) {
            mFindings.add(new JwtFinding(JwtFinding.Kind.WARN, "Admin claim",
                    "admin:true — test privilege escalation by modifying"));
        }
        if ("admin".equalsIgnoreCase(role)) {
            mFindings.add(new JwtFinding(JwtFinding.Kind.WARN, "Admin role",
                    "role:admin — test privilege escalation by modifying"));
        }
        if (email != null) {
            mFindings.add(new JwtFinding(JwtFinding.Kind.WARN, "PII in payload",
                    "email field is visible without signature verification"));
        }

        // List payload fields
        List<String> keys = extractJsonKeys(payloadJson);
        if (!keys.isEmpty()) {
            mFindings.add(new JwtFinding(JwtFinding.Kind.INFO, "Payload fields",
                    android.text.TextUtils.join(", ", keys)));
        }
    }

    // --------------- JSON helpers (no library) ---------------
    private String extractJsonString(String json, String key) {
        String search = "\"" + key + "\":";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int start = idx + search.length();
        while (start < json.length() && json.charAt(start) == ' ') start++;
        if (start >= json.length()) return null;
        if (json.charAt(start) == '"') {
            int end = json.indexOf('"', start + 1);
            if (end < 0) return null;
            return json.substring(start + 1, end);
        } else {
            // non-string value (boolean/number)
            int end = start;
            while (end < json.length() && ",}]".indexOf(json.charAt(end)) < 0) end++;
            return json.substring(start, end).trim();
        }
    }

    private Long extractJsonLong(String json, String key) {
        String val = extractJsonString(json, key);
        if (val == null) return null;
        try { return Long.parseLong(val.trim()); }
        catch (NumberFormatException e) { return null; }
    }

    private List<String> extractJsonKeys(String json) {
        List<String> keys = new ArrayList<>();
        int i = 0;
        while (i < json.length()) {
            int q1 = json.indexOf('"', i);
            if (q1 < 0) break;
            int q2 = json.indexOf('"', q1 + 1);
            if (q2 < 0) break;
            String candidate = json.substring(q1 + 1, q2);
            // Check if followed by ":"
            int colon = q2 + 1;
            while (colon < json.length() && json.charAt(colon) == ' ') colon++;
            if (colon < json.length() && json.charAt(colon) == ':') {
                keys.add(candidate);
            }
            i = q2 + 1;
        }
        return keys;
    }

    private String padBase64(String s) {
        int pad = (4 - s.length() % 4) % 4;
        StringBuilder sb = new StringBuilder(s);
        for (int i = 0; i < pad; i++) sb.append('=');
        return sb.toString();
    }

    private String formatEpoch(long epoch) {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)
                .format(new Date(epoch * 1000L));
    }
}
