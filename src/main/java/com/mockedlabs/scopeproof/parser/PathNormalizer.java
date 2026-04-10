package com.mockedlabs.scopeproof.parser;

import java.util.regex.Pattern;

/**
 * Converts dynamic URL path segments into reusable endpoint groups.
 * E.g. /users/123 and /users/456 both become /users/{id}.
 *
 * When {@code aggressive} is true (e.g. Intruder traffic), even single-digit
 * numeric segments are normalized to {id} so payload iterations collapse
 * into one endpoint row.
 */
public class PathNormalizer {

    private static final Pattern UUID_RE = Pattern.compile(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern HEX_TOKEN_RE = Pattern.compile(
        "^[0-9a-f]{16,}$", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern NUMERIC_ID_RE = Pattern.compile("^\\d{2,}$");
    private static final Pattern SINGLE_DIGIT_RE = Pattern.compile("^\\d$");
    private static final Pattern ALPHANUM_TOKEN_RE = Pattern.compile("^[a-zA-Z0-9_-]{20,}$");
    private static final Pattern HAS_DIGIT = Pattern.compile("\\d");

    public static String normalizeSegment(String segment) {
        return normalizeSegment(segment, false);
    }

    public static String normalizeSegment(String segment, boolean aggressive) {
        if (segment == null || segment.isEmpty()) return segment;
        if (UUID_RE.matcher(segment).matches()) return "{uuid}";
        if (HEX_TOKEN_RE.matcher(segment).matches()) return "{token}";
        if (NUMERIC_ID_RE.matcher(segment).matches()) return "{id}";
        if (aggressive && SINGLE_DIGIT_RE.matcher(segment).matches()) return "{id}";
        if (ALPHANUM_TOKEN_RE.matcher(segment).matches()
                && HAS_DIGIT.matcher(segment).find()) {
            return "{token}";
        }
        return segment;
    }

    public static String normalizePath(String path) {
        return normalizePath(path, false);
    }

    public static String normalizePath(String path, boolean aggressive) {
        if (path == null || path.isEmpty()) return "/";
        // Strip query string and fragment
        int qi = path.indexOf('?');
        if (qi >= 0) path = path.substring(0, qi);
        int hi = path.indexOf('#');
        if (hi >= 0) path = path.substring(0, hi);

        String[] segments = path.split("/", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) sb.append('/');
            sb.append(normalizeSegment(segments[i], aggressive));
        }
        String result = sb.toString();
        return result.isEmpty() ? "/" : result;
    }
}
