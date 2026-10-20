"""
fingerprints.py
----------------
The technology signature database. This is the only file most people
need to touch to add new detections -- it contains no logic, only data,
consumed by headers.py / html.py / engine.py.

Each signature dict has:
    name        - technology name shown to the user
    category    - CMS / Framework / JS Library / Web Server / CDN / etc.
    confidence  - default confidence level for a match on this signature
    version_re  - optional regex with a capture group for the version,
                  applied to the *matched string* when possible

HEADER_SIGNATURES: matched against individual header values.
    key: header name (case-insensitive)
    value: list of signature dicts, each with a `pattern` (regex) to
           search for within that header's value.

HTML_SIGNATURES: matched against the response body text.
    list of signature dicts, each with a `pattern` (regex).

COOKIE_SIGNATURES: matched against Set-Cookie header content.
"""

HEADER_SIGNATURES = {
    "server": [
        {"pattern": r"nginx(?:/([\d.]+))?", "name": "Nginx", "category": "Web Server", "confidence": "High"},
        {"pattern": r"apache(?:/([\d.]+))?", "name": "Apache", "category": "Web Server", "confidence": "High"},
        {"pattern": r"Microsoft-IIS(?:/([\d.]+))?", "name": "IIS", "category": "Web Server", "confidence": "High"},
        {"pattern": r"cloudflare", "name": "Cloudflare", "category": "CDN", "confidence": "High"},
        {"pattern": r"LiteSpeed", "name": "LiteSpeed", "category": "Web Server", "confidence": "High"},
        {"pattern": r"gunicorn(?:/([\d.]+))?", "name": "Gunicorn", "category": "Web Server", "confidence": "High"},
        {"pattern": r"openresty(?:/([\d.]+))?", "name": "OpenResty", "category": "Web Server", "confidence": "High"},
        {"pattern": r"caddy", "name": "Caddy", "category": "Web Server", "confidence": "High"},
    ],
    "x-powered-by": [
        {"pattern": r"PHP(?:/([\d.]+))?", "name": "PHP", "category": "Programming Language", "confidence": "High"},
        {"pattern": r"ASP\.NET", "name": "ASP.NET", "category": "Framework", "confidence": "High"},
        {"pattern": r"Express", "name": "Express.js", "category": "Framework", "confidence": "High"},
        {"pattern": r"Next\.js", "name": "Next.js", "category": "JS Framework", "confidence": "High"},
    ],
    "x-generator": [
        {"pattern": r"Drupal(?:\s*([\d.]+))?", "name": "Drupal", "category": "CMS", "confidence": "High"},
    ],
    "x-drupal-cache": [
        {"pattern": r".*", "name": "Drupal", "category": "CMS", "confidence": "High"},
    ],
    "x-aspnet-version": [
        {"pattern": r"([\d.]+)", "name": "ASP.NET", "category": "Framework", "confidence": "High"},
    ],
    "via": [
        {"pattern": r"varnish", "name": "Varnish", "category": "CDN/Cache", "confidence": "Medium"},
    ],
    "x-shopify-stage": [
        {"pattern": r".*", "name": "Shopify", "category": "E-commerce", "confidence": "High"},
    ],
    "x-magento-cache-debug": [
        {"pattern": r".*", "name": "Magento", "category": "E-commerce", "confidence": "High"},
    ],
    "cf-ray": [
        {"pattern": r".*", "name": "Cloudflare", "category": "CDN", "confidence": "High"},
    ],
    "x-vercel-id": [
        {"pattern": r".*", "name": "Vercel", "category": "Hosting/CDN", "confidence": "High"},
    ],
    "x-amz-cf-id": [
        {"pattern": r".*", "name": "Amazon CloudFront", "category": "CDN", "confidence": "High"},
    ],
}

COOKIE_SIGNATURES = [
    {"pattern": r"PHPSESSID", "name": "PHP", "category": "Programming Language", "confidence": "Medium"},
    {"pattern": r"wordpress_logged_in|wp-settings", "name": "WordPress", "category": "CMS", "confidence": "High"},
    {"pattern": r"CAKEPHP", "name": "CakePHP", "category": "Framework", "confidence": "Medium"},
    {"pattern": r"laravel_session", "name": "Laravel", "category": "Framework", "confidence": "High"},
    {"pattern": r"django(?:sessionid)?", "name": "Django", "category": "Framework", "confidence": "Medium"},
    {"pattern": r"JSESSIONID", "name": "Java (Servlet/JSP)", "category": "Programming Language", "confidence": "Medium"},
    {"pattern": r"ci_session", "name": "CodeIgniter", "category": "Framework", "confidence": "Medium"},
    {"pattern": r"__cfduid|cf_clearance", "name": "Cloudflare", "category": "CDN", "confidence": "High"},
]

HTML_SIGNATURES = [
    # CMS
    {"pattern": r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)', "name": "WordPress", "category": "CMS", "confidence": "High"},
    {"pattern": r"wp-content|wp-includes", "name": "WordPress", "category": "CMS", "confidence": "High"},
    {"pattern": r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla', "name": "Joomla", "category": "CMS", "confidence": "High"},
    {"pattern": r"/sites/default/files|Drupal\.settings", "name": "Drupal", "category": "CMS", "confidence": "High"},
    {"pattern": r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Wix', "name": "Wix", "category": "CMS", "confidence": "High"},
    {"pattern": r"cdn\.shopify\.com|Shopify\.theme", "name": "Shopify", "category": "E-commerce", "confidence": "High"},
    {"pattern": r"static\.squarespace\.com", "name": "Squarespace", "category": "CMS", "confidence": "High"},
    {"pattern": r"/wp-json/|woocommerce", "name": "WooCommerce", "category": "E-commerce", "confidence": "Medium"},
    {"pattern": r"Magento", "name": "Magento", "category": "E-commerce", "confidence": "Medium"},
    {"pattern": r"ghost-url|content=\"Ghost", "name": "Ghost", "category": "CMS", "confidence": "Medium"},

    # JS frameworks / libraries
    {"pattern": r"__NEXT_DATA__|_next/static", "name": "Next.js", "category": "JS Framework", "confidence": "High"},
    {"pattern": r"__NUXT__|_nuxt/", "name": "Nuxt", "category": "JS Framework", "confidence": "High"},
    {"pattern": r'ng-version=["\']([\d.]+)', "name": "Angular", "category": "JS Framework", "confidence": "High"},
    {"pattern": r"data-reactroot|react-dom", "name": "React", "category": "JS Framework", "confidence": "Medium"},
    {"pattern": r"id=[\"']__vue|vue\.js|__VUE__", "name": "Vue.js", "category": "JS Framework", "confidence": "Medium"},
    {"pattern": r"svelte-", "name": "Svelte", "category": "JS Framework", "confidence": "Medium"},
    {"pattern": r"jquery(?:-|\.)([\d.]+)?", "name": "jQuery", "category": "JS Library", "confidence": "High"},
    {"pattern": r"bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js", "name": "Bootstrap", "category": "CSS Framework", "confidence": "High"},
    {"pattern": r"tailwindcss|tailwind\.css", "name": "Tailwind CSS", "category": "CSS Framework", "confidence": "Medium"},

    # Backend frameworks (from body hints, e.g. debug pages / error text)
    {"pattern": r"Laravel", "name": "Laravel", "category": "Framework", "confidence": "Medium"},
    {"pattern": r"csrfmiddlewaretoken|Django", "name": "Django", "category": "Framework", "confidence": "Medium"},
    {"pattern": r"Ruby on Rails|X-Runtime", "name": "Ruby on Rails", "category": "Framework", "confidence": "Low"},

    # Analytics
    {"pattern": r"www\.google-analytics\.com|gtag\(", "name": "Google Analytics", "category": "Analytics", "confidence": "High"},
    {"pattern": r"googletagmanager\.com", "name": "Google Tag Manager", "category": "Analytics", "confidence": "High"},
    {"pattern": r"cdn\.segment\.com", "name": "Segment", "category": "Analytics", "confidence": "Medium"},
    {"pattern": r"static\.hotjar\.com", "name": "Hotjar", "category": "Analytics", "confidence": "Medium"},

    # CDN hints visible in markup
    {"pattern": r"cdnjs\.cloudflare\.com", "name": "Cloudflare CDN", "category": "CDN", "confidence": "Medium"},
    {"pattern": r"ajax\.googleapis\.com", "name": "Google Hosted Libraries", "category": "CDN", "confidence": "Low"},
]
