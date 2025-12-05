/*
 * This file is part of cSploit.
 *
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */

package org.csploit.android.helpers;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.view.View;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.view.animation.AnimationSet;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.LinearInterpolator;
import android.view.animation.RotateAnimation;
import android.view.animation.ScaleAnimation;
import android.view.animation.TranslateAnimation;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * AnimationHelper - Smooth animations and transitions utility
 *
 * Provides streamlined animation utilities for common UI transitions and effects.
 *
 * Features:
 * - Fade in/out animations
 * - Slide in/out animations
 * - Scale animations
 * - Rotation animations
 * - Bounce and spring effects
 * - Shake animations
 * - Pulse animations
 * - Configurable duration and interpolators
 * - Animation listeners and callbacks
 *
 * Usage:
 * {@code
 * // Fade in animation
 * AnimationHelper.fadeIn(view, 300);
 *
 * // Slide animation
 * AnimationHelper.slideInFromLeft(view, 400);
 *
 * // Scale with callback
 * AnimationHelper.scale(view, 0.8f, 1.0f, 500, () -> {
 *     LoggingHelper.d("Animation", "Scale complete");
 * });
 *
 * // Bounce effect
 * AnimationHelper.bounce(view, 500);
 * }
 *
 * @author cSploit Team
 * @version 1.0
 */
public final class AnimationHelper {

    private static final String TAG = "AnimationHelper";

    // Default animation durations (ms)
    private static final long DEFAULT_SHORT_DURATION = 200;
    private static final long DEFAULT_DURATION = 500;
    private static final long DEFAULT_LONG_DURATION = 1000;

    // Private constructor to prevent instantiation
    private AnimationHelper() {}

    /**
     * Fade in animation
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void fadeIn(@NonNull View view, long duration) {
        fadeIn(view, duration, null);
    }

    /**
     * Fade in animation with callback
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     * @param onComplete callback when animation completes
     */
    public static void fadeIn(@NonNull View view, long duration, @Nullable Runnable onComplete) {
        ObjectAnimator animator = ObjectAnimator.ofFloat(view, "alpha", 0f, 1f);
        animator.setDuration(duration);
        animator.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                view.setAlpha(1f);
                if (onComplete != null) onComplete.run();
            }
        });
        animator.start();
        LoggingHelper.d(TAG, "Fade in: " + view.getClass().getSimpleName());
    }

    /**
     * Fade out animation
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void fadeOut(@NonNull View view, long duration) {
        fadeOut(view, duration, null);
    }

    /**
     * Fade out animation with callback
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     * @param onComplete callback when animation completes
     */
    public static void fadeOut(@NonNull View view, long duration, @Nullable Runnable onComplete) {
        ObjectAnimator animator = ObjectAnimator.ofFloat(view, "alpha", 1f, 0f);
        animator.setDuration(duration);
        animator.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                view.setAlpha(0f);
                view.setVisibility(View.GONE);
                if (onComplete != null) onComplete.run();
            }
        });
        animator.start();
        LoggingHelper.d(TAG, "Fade out: " + view.getClass().getSimpleName());
    }

    /**
     * Slide in from left animation
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void slideInFromLeft(@NonNull View view, long duration) {
        TranslateAnimation animation = new TranslateAnimation(-view.getWidth(), 0, 0, 0);
        animation.setDuration(duration);
        animation.setInterpolator(new DecelerateInterpolator());
        view.startAnimation(animation);
        LoggingHelper.d(TAG, "Slide in from left: " + view.getClass().getSimpleName());
    }

    /**
     * Slide out to left animation
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void slideOutToLeft(@NonNull View view, long duration) {
        TranslateAnimation animation = new TranslateAnimation(0, -view.getWidth(), 0, 0);
        animation.setDuration(duration);
        animation.setInterpolator(new DecelerateInterpolator());
        animation.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {}

            @Override
            public void onAnimationEnd(Animation animation) {
                view.setVisibility(View.GONE);
            }

            @Override
            public void onAnimationRepeat(Animation animation) {}
        });
        view.startAnimation(animation);
        LoggingHelper.d(TAG, "Slide out to left: " + view.getClass().getSimpleName());
    }

    /**
     * Slide in from right animation
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void slideInFromRight(@NonNull View view, long duration) {
        TranslateAnimation animation = new TranslateAnimation(view.getWidth(), 0, 0, 0);
        animation.setDuration(duration);
        animation.setInterpolator(new DecelerateInterpolator());
        view.startAnimation(animation);
        LoggingHelper.d(TAG, "Slide in from right: " + view.getClass().getSimpleName());
    }

    /**
     * Slide in from top animation
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void slideInFromTop(@NonNull View view, long duration) {
        TranslateAnimation animation = new TranslateAnimation(0, 0, -view.getHeight(), 0);
        animation.setDuration(duration);
        animation.setInterpolator(new DecelerateInterpolator());
        view.startAnimation(animation);
        LoggingHelper.d(TAG, "Slide in from top: " + view.getClass().getSimpleName());
    }

    /**
     * Slide in from bottom animation
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void slideInFromBottom(@NonNull View view, long duration) {
        TranslateAnimation animation = new TranslateAnimation(0, 0, view.getHeight(), 0);
        animation.setDuration(duration);
        animation.setInterpolator(new DecelerateInterpolator());
        view.startAnimation(animation);
        LoggingHelper.d(TAG, "Slide in from bottom: " + view.getClass().getSimpleName());
    }

    /**
     * Scale animation
     *
     * @param view view to animate
     * @param fromScale starting scale value
     * @param toScale ending scale value
     * @param duration animation duration in milliseconds
     */
    public static void scale(@NonNull View view, float fromScale, float toScale, long duration) {
        scale(view, fromScale, toScale, duration, null);
    }

    /**
     * Scale animation with callback
     *
     * @param view view to animate
     * @param fromScale starting scale value
     * @param toScale ending scale value
     * @param duration animation duration in milliseconds
     * @param onComplete callback when animation completes
     */
    public static void scale(@NonNull View view, float fromScale, float toScale,
                            long duration, @Nullable Runnable onComplete) {
        ScaleAnimation animation = new ScaleAnimation(fromScale, toScale, fromScale, toScale,
                Animation.RELATIVE_TO_SELF, 0.5f, Animation.RELATIVE_TO_SELF, 0.5f);
        animation.setDuration(duration);
        animation.setInterpolator(new DecelerateInterpolator());
        animation.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {}

            @Override
            public void onAnimationEnd(Animation animation) {
                if (onComplete != null) onComplete.run();
            }

            @Override
            public void onAnimationRepeat(Animation animation) {}
        });
        view.startAnimation(animation);
        LoggingHelper.d(TAG, "Scale: " + view.getClass().getSimpleName());
    }

    /**
     * Rotate animation (360 degrees)
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void rotate(@NonNull View view, long duration) {
        rotate(view, 0, 360, duration, null);
    }

    /**
     * Rotate animation with custom angles
     *
     * @param view view to animate
     * @param fromDegrees starting rotation angle
     * @param toDegrees ending rotation angle
     * @param duration animation duration in milliseconds
     * @param onComplete callback when animation completes
     */
    public static void rotate(@NonNull View view, float fromDegrees, float toDegrees,
                             long duration, @Nullable Runnable onComplete) {
        RotateAnimation animation = new RotateAnimation(fromDegrees, toDegrees,
                Animation.RELATIVE_TO_SELF, 0.5f, Animation.RELATIVE_TO_SELF, 0.5f);
        animation.setDuration(duration);
        animation.setInterpolator(new LinearInterpolator());
        animation.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {}

            @Override
            public void onAnimationEnd(Animation animation) {
                if (onComplete != null) onComplete.run();
            }

            @Override
            public void onAnimationRepeat(Animation animation) {}
        });
        view.startAnimation(animation);
        LoggingHelper.d(TAG, "Rotate: " + view.getClass().getSimpleName());
    }

    /**
     * Bounce animation
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void bounce(@NonNull View view, long duration) {
        ObjectAnimator scaleX = ObjectAnimator.ofFloat(view, "scaleX", 1f, 0.9f, 1.1f, 1f);
        ObjectAnimator scaleY = ObjectAnimator.ofFloat(view, "scaleY", 1f, 0.9f, 1.1f, 1f);

        scaleX.setDuration(duration);
        scaleY.setDuration(duration);

        scaleX.start();
        scaleY.start();

        LoggingHelper.d(TAG, "Bounce: " + view.getClass().getSimpleName());
    }

    /**
     * Shake animation (side to side)
     *
     * @param view view to animate
     */
    public static void shake(@NonNull View view) {
        shake(view, DEFAULT_DURATION);
    }

    /**
     * Shake animation with custom duration
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void shake(@NonNull View view, long duration) {
        TranslateAnimation animation = new TranslateAnimation(0, 10, 0, 0);
        animation.setDuration(50);
        animation.setRepeatCount(4);
        animation.setRepeatMode(Animation.REVERSE);
        view.startAnimation(animation);
        LoggingHelper.d(TAG, "Shake: " + view.getClass().getSimpleName());
    }

    /**
     * Pulse animation (grow and shrink)
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void pulse(@NonNull View view, long duration) {
        ObjectAnimator scaleX = ObjectAnimator.ofFloat(view, "scaleX", 1f, 1.2f, 1f);
        ObjectAnimator scaleY = ObjectAnimator.ofFloat(view, "scaleY", 1f, 1.2f, 1f);

        scaleX.setDuration(duration);
        scaleY.setDuration(duration);

        scaleX.start();
        scaleY.start();

        LoggingHelper.d(TAG, "Pulse: " + view.getClass().getSimpleName());
    }

    /**
     * Flip animation (vertical)
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void flipVertical(@NonNull View view, long duration) {
        ObjectAnimator rotationX = ObjectAnimator.ofFloat(view, "rotationX", 0f, 360f);
        rotationX.setDuration(duration);
        rotationX.start();
        LoggingHelper.d(TAG, "Flip vertical: " + view.getClass().getSimpleName());
    }

    /**
     * Flip animation (horizontal)
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void flipHorizontal(@NonNull View view, long duration) {
        ObjectAnimator rotationY = ObjectAnimator.ofFloat(view, "rotationY", 0f, 360f);
        rotationY.setDuration(duration);
        rotationY.start();
        LoggingHelper.d(TAG, "Flip horizontal: " + view.getClass().getSimpleName());
    }

    /**
     * Swing animation (pendulum)
     *
     * @param view view to animate
     * @param duration animation duration in milliseconds
     */
    public static void swing(@NonNull View view, long duration) {
        ObjectAnimator rotation = ObjectAnimator.ofFloat(view, "rotation", 0f, -15f, 15f, -15f, 15f, 0f);
        rotation.setDuration(duration);
        rotation.start();
        LoggingHelper.d(TAG, "Swing: " + view.getClass().getSimpleName());
    }

    /**
     * Custom animation with value animator
     *
     * @param duration animation duration in milliseconds
     * @param interpolator animation interpolator
     * @param updateListener value animator update listener
     * @return animator
     */
    @NonNull
    public static ValueAnimator custom(long duration, @Nullable Interpolator interpolator,
                                       @NonNull ValueAnimator.AnimatorUpdateListener updateListener) {
        ValueAnimator animator = ValueAnimator.ofFloat(0f, 1f);
        animator.setDuration(duration);
        if (interpolator != null) animator.setInterpolator(interpolator);
        animator.addUpdateListener(updateListener);
        animator.start();
        return animator;
    }

    /**
     * Cancel all animations on a view
     *
     * @param view view to clear animations
     */
    public static void clearAnimations(@NonNull View view) {
        view.clearAnimation();
        LoggingHelper.d(TAG, "Animations cleared: " + view.getClass().getSimpleName());
    }
}
