package com.artex.workflowfixture;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.view.View;
import android.view.KeyEvent;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.Locale;

public final class MainActivity extends Activity {
    private EditText input;
    private TextView result;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(20);
        layout.setPadding(padding, padding, padding, padding);

        input = new EditText(this);
        input.setSingleLine(true);
        input.setHint("Enter a value");
        input.setContentDescription("fixture-input");
        input.setImeOptions(EditorInfo.IME_ACTION_DONE);
        layout.addView(input, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        Button compute = new Button(this);
        compute.setText("Compute");
        compute.setContentDescription("fixture-compute");
        layout.addView(compute, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        result = new TextView(this);
        result.setText("Ready");
        result.setContentDescription("fixture-result");
        layout.addView(result, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        setContentView(layout);
        input.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView view, int actionId, KeyEvent event) {
                if (actionId == EditorInfo.IME_ACTION_DONE) {
                    closeKeyboard();
                    return true;
                }
                return false;
            }
        });
        compute.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String value = transform(input.getText().toString());
                result.setText(value);
                closeKeyboard();
            }
        });
    }

    public static String transform(String input) {
        return "ECHO:" + input.trim().toUpperCase(Locale.ROOT);
    }

    private void closeKeyboard() {
        InputMethodManager manager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
        if (manager != null) {
            manager.hideSoftInputFromWindow(input.getWindowToken(), 0);
        }
        input.clearFocus();
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
