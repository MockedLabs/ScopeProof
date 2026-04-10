package com.mockedlabs.scopeproof.model;

/**
 * A single attack signature match found in an HTTP request.
 */
public class AttackPattern {

    private final String match;
    private final int offset;

    public AttackPattern(String match, int offset) {
        this.match = match;
        this.offset = offset;
    }

    public String getMatch() { return match; }
    public int getOffset() { return offset; }
}
