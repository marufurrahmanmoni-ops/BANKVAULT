package com.bankvault.core.util

import java.util.Base64

internal fun ByteArray.b64(): String = Base64.getEncoder().withoutPadding().encodeToString(this)
internal fun String.unb64(): ByteArray = Base64.getDecoder().decode(this)

/** Overwrite sensitive buffers as soon as they are no longer needed. */
fun CharArray.wipe() = fill('\u0000')
fun ByteArray.wipe() = fill(0)
