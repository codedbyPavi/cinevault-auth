/**
 * script.js - Shared frontend logic for Register and Login
 * Handles form submit, API calls, redirects, and error/success messages.
 */

const API_BASE = ''; // same origin as the server

/**
 * Shows a message in the message box (error or success).
 */
function showMessage(elementId, text, isError = true) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = text;
  el.className = 'message ' + (isError ? 'error' : 'success') + ' show';
}

/**
 * Hides the message box.
 */
function hideMessage(elementId) {
  const el = document.getElementById(elementId);
  if (el) el.classList.remove('show');
}

/**
 * Register form: collect user_id, name, email, phone, password.
 * On success, redirect to login page.
 */
function initRegisterForm() {
  const form = document.getElementById('register-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideMessage('register-message');

    const submitBtn = form.querySelector('button[type="submit"]');
    submitBtn.disabled = true;

    const payload = {
      user_id: form.user_id.value.trim(),
      name: form.name.value.trim(),
      email: form.email.value.trim(),
      phone: form.phone.value.trim(),
      password: form.password.value,
    };

    try {
      const res = await fetch(API_BASE + '/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (data.success) {
        showMessage('register-message', data.message || 'Registration successful. Redirecting...', false);
        if (typeof window.fastRedirect === 'function') {
          window.fastRedirect('/login.html');
        } else {
          setTimeout(() => { window.location.href = '/login.html'; }, 800);
        }
      } else {
        showMessage('register-message', data.message || 'Registration failed.');
        submitBtn.disabled = false;
      }
    } catch (err) {
      showMessage('register-message', 'Network error. Please try again.');
      submitBtn.disabled = false;
    }
  });
}

/**
 * Login form: user enters User ID or Email + password.
 * On success, redirect to https://netflix-landing-eta.vercel.app/
 * On failure, show error message.
 */
function initLoginForm() {
  const form = document.getElementById('login-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideMessage('login-message');

    const submitBtn = form.querySelector('button[type="submit"]');
    submitBtn.disabled = true;

    const payload = {
      loginId: form.loginId.value.trim(),
      password: form.password.value,
    };

    try {
      const res = await fetch(API_BASE + '/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (data.success) {
        showMessage('login-message', data.message || 'Login successful! Redirecting...', false);
        if (typeof window.fastRedirect === 'function') {
          window.fastRedirect('https://netflix-landing-eta.vercel.app/');
        } else {
          setTimeout(() => { window.location.href = 'https://netflix-landing-eta.vercel.app/'; }, 800);
        }
      } else {
        showMessage('login-message', data.message || 'Invalid credentials.');
        submitBtn.disabled = false;
      }
    } catch (err) {
      showMessage('login-message', 'Network error. Please try again.');
      submitBtn.disabled = false;
    }
  });
}

// Run the right initializer based on which page we're on
document.addEventListener('DOMContentLoaded', () => {
  initRegisterForm();
  initLoginForm();
});
