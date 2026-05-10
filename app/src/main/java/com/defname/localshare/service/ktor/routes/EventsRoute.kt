// SPDX-FileCopyrightText: 2026 2026 defname
//
// SPDX-License-Identifier: GPL-3.0-or-later

package com.defname.localshare.service.ktor.routes

import android.util.Log
import com.defname.localshare.data.CallAttributes
import com.defname.localshare.data.ConnectionLogsRepository
import com.defname.localshare.data.ServiceRepository
import com.defname.localshare.domain.model.DisconnectReason
import com.defname.localshare.domain.model.FileInfo
import com.defname.localshare.domain.model.SharedContent
import com.defname.localshare.domain.repository.SettingsRepository
import com.defname.localshare.service.ServerSecurityHandler
import com.defname.localshare.service.ktor.json.toJsonString
import io.ktor.http.CacheControl
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.cacheControl
import io.ktor.server.response.header
import io.ktor.server.response.respondOutputStream
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.io.BufferedWriter

// ─── Delta flow helpers ───────────────────────────────────────────────────────

sealed class FlowDelta<T>(val obj: T) {
    class Added<T>(obj: T) : FlowDelta<T>(obj)
    class Removed<T>(obj: T) : FlowDelta<T>(obj)
}

private fun <T, K> Flow<List<T>>.asDeltaEvents(key: (T) -> K): Flow<FlowDelta<T>> = flow {
    var oldList = emptyList<T>()
    collect { newList ->
        newList.filter { n -> oldList.none { key(it) == key(n) } }.forEach { emit(FlowDelta.Added(it)) }
        oldList.filter { o -> newList.none { key(it) == key(o) } }.forEach { emit(FlowDelta.Removed(it)) }
        oldList = newList
    }
}

@JvmName("fileInfoDeltaEvents")
fun Flow<List<FileInfo>>.asDeltaEvents() = asDeltaEvents { it.id }

@JvmName("sharedContentDeltaEvents")
fun Flow<List<SharedContent>>.asDeltaEvents() = asDeltaEvents { it.id }

// ─── SSE write helpers ────────────────────────────────────────────────────────

fun BufferedWriter.writeEvent(eventName: String, data: String) {
    write("event: $eventName\n")
    write("data: $data\n\n")
    flush()
}

fun BufferedWriter.writeHeartbeat() {
    write(": heartbeat\n\n")
    flush()
}

// ─── Route ────────────────────────────────────────────────────────────────────

fun Route.getEvents(
    securityHandler: ServerSecurityHandler,
    serviceRepository: ServiceRepository,
    settingsRepository: SettingsRepository,
    connectionLogsRepository: ConnectionLogsRepository
) {
    get("/{token}/events") {
        if (!securityHandler.verifyAccess(call)) {
            return@get call.respondText("No Access.", status = HttpStatusCode.Forbidden)
        }

        call.response.cacheControl(CacheControl.NoCache(CacheControl.Visibility.Private))
        call.response.header(HttpHeaders.ContentType, ContentType.Text.EventStream.toString())
        call.response.header(HttpHeaders.Connection, "keep-alive")
        call.response.header("X-Accel-Buffering", "no")

        call.respondOutputStream {
            val writer = bufferedWriter()
            var disconnectReason: DisconnectReason = DisconnectReason.ServerShutdown

            try {
                coroutineScope {
                    // Get heartbeat period — settingsFlow is a plain Flow so we .first() it once
                    val heartbeatMs = settingsRepository.settingsFlow.first().sseHeartbeatPeriodSeconds * 1000L

                    // Send full current file list so reconnecting browsers restore their state
                    val currentFiles = serviceRepository.fileList.first()
                    val initJson = "[" + currentFiles.joinToString(",") { it.toJsonString() } + "]"
                    writer.writeEvent("init", initJson)

                    val sharedContentList = serviceRepository.runtimeState
                        .map { it.sharedContentList }
                        .stateIn(this, SharingStarted.Eagerly, emptyList())

                    // File delta collector
                    launch {
                        serviceRepository.fileList.asDeltaEvents().collect { delta ->
                            if (!securityHandler.isStillAllowed(call)) {
                                disconnectReason = DisconnectReason.Unexpected.AuthInvalid
                                this@coroutineScope.cancel("Access revoked")
                                return@collect
                            }
                            when (delta) {
                                is FlowDelta.Added -> writer.writeEvent("add", delta.obj.toJsonString())
                                is FlowDelta.Removed -> writer.writeEvent("remove", delta.obj.id)
                            }
                        }
                    }

                    // Shared content delta collector
                    launch {
                        sharedContentList.asDeltaEvents().collect { delta ->
                            if (!securityHandler.isStillAllowed(call)) {
                                disconnectReason = DisconnectReason.Unexpected.AuthInvalid
                                this@coroutineScope.cancel("Access revoked")
                                return@collect
                            }
                            when (delta) {
                                is FlowDelta.Added ->
                                    writer.writeEvent("addSharedContent", delta.obj.toJsonString())
                                is FlowDelta.Removed ->
                                    writer.writeEvent("removeSharedContent", delta.obj.id.toString())
                            }
                        }
                    }

                    // Heartbeat — only uses non-suspending isStillAllowed, no approval re-trigger
                    launch {
                        while (true) {
                            delay(heartbeatMs)
                            if (!securityHandler.isStillAllowed(call)) {
                                disconnectReason = DisconnectReason.Unexpected.AuthInvalid
                                this@coroutineScope.cancel("Access revoked")
                            }
                            writer.writeHeartbeat()
                        }
                    }
                }
            } catch (e: Exception) {
                if (e !is CancellationException) {
                    disconnectReason = DisconnectReason.Unexpected.ClientGone
                    Log.d("EventsRoute", "SSE error: ${e.message}")
                }
            } finally {
                val connectionId = call.attributes.getOrNull(CallAttributes.connectionId)
                if (connectionId != null) {
                    connectionLogsRepository.clientDisconnected(connectionId, disconnectReason)
                }
            }
        }
    }
}
