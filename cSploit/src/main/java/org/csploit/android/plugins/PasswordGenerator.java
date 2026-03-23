package org.csploit.android.plugins;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import org.csploit.android.BuildConfig;
import org.csploit.android.R;
import org.csploit.android.core.Plugin;
import org.csploit.android.net.Target;

import java.security.SecureRandom;

public class PasswordGenerator extends Plugin {

    private static final int[] LENGTHS = {8, 12, 16, 20, 24, 32, 48, 64};
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS    = "0123456789";
    private static final String SYMBOLS   = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    private Spinner mLengthSpinner;
    private CheckBox mUppercase, mLowercase, mDigits, mSymbols;
    private Button mGenerateBtn, mCopyBtn;
    private TextView mResultView, mStrengthView;

    private final SecureRandom mRandom = new SecureRandom();

    // --------------- constructor ---------------
    public PasswordGenerator() {
        super(R.string.password_generator, R.string.password_generator_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE, Target.Type.NETWORK},
                R.layout.plugin_password_generator, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mLengthSpinner = findViewById(R.id.pwdLengthSpinner);
        mUppercase     = findViewById(R.id.pwdUppercase);
        mLowercase     = findViewById(R.id.pwdLowercase);
        mDigits        = findViewById(R.id.pwdDigits);
        mSymbols       = findViewById(R.id.pwdSymbols);
        mGenerateBtn   = findViewById(R.id.pwdGenerateButton);
        mResultView    = findViewById(R.id.pwdResult);
        mStrengthView  = findViewById(R.id.pwdStrength);
        mCopyBtn       = findViewById(R.id.pwdCopyButton);

        // Populate spinner
        String[] lengthLabels = new String[LENGTHS.length];
        for (int i = 0; i < LENGTHS.length; i++) lengthLabels[i] = String.valueOf(LENGTHS[i]);
        ArrayAdapter<String> spinnerAdapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item, lengthLabels);
        spinnerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        mLengthSpinner.setAdapter(spinnerAdapter);
        mLengthSpinner.setSelection(2); // default 16

        // Defaults
        mUppercase.setChecked(true);
        mLowercase.setChecked(true);
        mDigits.setChecked(true);
        mSymbols.setChecked(false);

        mGenerateBtn.setOnClickListener(v -> generatePassword());
        mCopyBtn.setOnClickListener(v -> copyToClipboard());

        // Generate one on create
        generatePassword();
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // --------------- logic ---------------
    private void generatePassword() {
        int length = LENGTHS[mLengthSpinner.getSelectedItemPosition()];

        StringBuilder charset = new StringBuilder();
        if (mLowercase.isChecked()) charset.append(LOWERCASE);
        if (mUppercase.isChecked()) charset.append(UPPERCASE);
        if (mDigits.isChecked())    charset.append(DIGITS);
        if (mSymbols.isChecked())   charset.append(SYMBOLS);

        if (charset.length() == 0) {
            mResultView.setText("Select at least one character set");
            mStrengthView.setText("");
            return;
        }

        // Guarantee at least one char from each selected set
        StringBuilder password = new StringBuilder();
        if (mLowercase.isChecked()) password.append(LOWERCASE.charAt(mRandom.nextInt(LOWERCASE.length())));
        if (mUppercase.isChecked()) password.append(UPPERCASE.charAt(mRandom.nextInt(UPPERCASE.length())));
        if (mDigits.isChecked())    password.append(DIGITS.charAt(mRandom.nextInt(DIGITS.length())));
        if (mSymbols.isChecked())   password.append(SYMBOLS.charAt(mRandom.nextInt(SYMBOLS.length())));

        while (password.length() < length) {
            password.append(charset.charAt(mRandom.nextInt(charset.length())));
        }

        // Shuffle
        char[] arr = password.toString().toCharArray();
        for (int i = arr.length - 1; i > 0; i--) {
            int j = mRandom.nextInt(i + 1);
            char tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
        }

        String pwd = new String(arr, 0, length);
        mResultView.setText(pwd);

        // Strength
        int diversity = (mLowercase.isChecked() ? 1 : 0)
                + (mUppercase.isChecked() ? 1 : 0)
                + (mDigits.isChecked() ? 1 : 0)
                + (mSymbols.isChecked() ? 1 : 0);

        String strength;
        if (length < 8) {
            strength = "Weak";
        } else if (length < 12) {
            strength = diversity >= 3 ? "Fair" : "Weak";
        } else if (length < 16) {
            strength = diversity >= 3 ? "Good" : "Fair";
        } else if (length < 24) {
            strength = diversity >= 3 ? "Strong" : "Good";
        } else {
            strength = diversity >= 3 ? "Very Strong" : "Strong";
        }
        mStrengthView.setText("Strength: " + strength);
    }

    private void copyToClipboard() {
        String pwd = mResultView.getText().toString();
        if (pwd.isEmpty()) return;
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("password", pwd));
        Toast.makeText(this, "Password copied", Toast.LENGTH_SHORT).show();
    }
}
