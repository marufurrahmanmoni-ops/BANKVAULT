package com.bankvault.core.threat

/**
 * IDN homograph and visual-confusion detection.
 * Uses Unicode script detection plus a confusable "skeleton" (subset of Unicode TR39 confusables
 * relevant to Latin look-alikes) so that "bкash", "bkаsh" (Cyrillic) and "bkash" compare equal.
 */
object Homograph {
    private val CONFUSABLES: Map<Char, String> = mapOf(
        // Cyrillic
        'а' to "a", 'в' to "b", 'е' to "e", 'ё' to "e", 'к' to "k", 'м' to "m", 'н' to "h", 'о' to "o",
        'р' to "p", 'с' to "c", 'т' to "t", 'у' to "y", 'х' to "x", 'ѕ' to "s", 'і' to "i", 'ј' to "j",
        'ԁ' to "d", 'ԛ' to "q", 'ԝ' to "w", 'һ' to "h", 'ӏ' to "l", 'ь' to "b", 'п' to "n", 'г' to "r",
        // Greek
        'α' to "a", 'β' to "b", 'ε' to "e", 'ι' to "i", 'κ' to "k", 'ν' to "v", 'ο' to "o", 'ρ' to "p",
        'τ' to "t", 'υ' to "u", 'χ' to "x", 'ω' to "w", 'η' to "n",
        // Latin extended look-alikes
        'ı' to "i", 'ł' to "l", 'ɡ' to "g", 'ɑ' to "a", 'ǀ' to "l", 'ß' to "ss",
        // ASCII digit/letter tricks
        '0' to "o", '1' to "l", '3' to "e", '5' to "s", '@' to "a", '$' to "s",
    )

    enum class Script { LATIN, CYRILLIC, GREEK, BENGALI, ARABIC, HAN, OTHER, COMMON }

    fun scriptOf(c: Char): Script {
        if (c.isDigit() || c == '-' || c == '.') return Script.COMMON
        return when (Character.UnicodeScript.of(c.code)) {
            Character.UnicodeScript.LATIN -> Script.LATIN
            Character.UnicodeScript.CYRILLIC -> Script.CYRILLIC
            Character.UnicodeScript.GREEK -> Script.GREEK
            Character.UnicodeScript.BENGALI -> Script.BENGALI
            Character.UnicodeScript.ARABIC -> Script.ARABIC
            Character.UnicodeScript.HAN -> Script.HAN
            Character.UnicodeScript.COMMON, Character.UnicodeScript.INHERITED -> Script.COMMON
            else -> Script.OTHER
        }
    }

    /** True if a single label mixes scripts in a way legitimate domains basically never do. */
    fun hasMixedScripts(label: String): Boolean {
        val scripts = label.map(::scriptOf).filter { it != Script.COMMON }.toSet()
        return scripts.size > 1
    }

    /** Non-Latin label whose skeleton is pure ASCII – a whole-script spoof (e.g. all-Cyrillic "раураl"). */
    fun isWholeScriptLatinLookalike(label: String): Boolean {
        val scripts = label.map(::scriptOf).filter { it != Script.COMMON }.toSet()
        if (scripts.isEmpty() || scripts == setOf(Script.LATIN)) return false
        val sk = skeleton(label)
        return sk.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
    }

    fun skeleton(s: String): String {
        val sb = StringBuilder()
        for (c in s.lowercase()) sb.append(CONFUSABLES[c] ?: c.toString())
        return sb.toString()
            .replace("rn", "m")
            .replace("vv", "w")
            .replace("cl", "d")
    }
}

object EditDistance {
    /** Optimal-string-alignment Damerau–Levenshtein (transpositions count as 1). */
    fun damerau(a: String, b: String): Int {
        val d = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) d[i][0] = i
        for (j in 0..b.length) d[0][j] = j
        for (i in 1..a.length) for (j in 1..b.length) {
            val cost = if (a[i - 1] == b[j - 1]) 0 else 1
            d[i][j] = minOf(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) d[i][j] = minOf(d[i][j], d[i - 2][j - 2] + 1)
        }
        return d[a.length][b.length]
    }
}
