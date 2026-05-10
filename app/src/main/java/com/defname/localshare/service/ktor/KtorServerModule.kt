// SPDX-FileCopyrightText: 2026 2026 defname
//
// SPDX-License-Identifier: GPL-3.0-or-later

package com.defname.localshare.service.ktor

import android.content.Context
import com.defname.localshare.data.CallAttributes
import com.defname.localshare.data.ConnectionLogsRepository
import com.defname.localshare.data.FileInfoProvider
import com.defname.localshare.data.ServiceRepository
import com.defname.localshare.domain.model.DisconnectReason
import com.defname.localshare.domain.repository.SettingsRepository
import com.defname.localshare.service.ServerSecurityHandler
import com.defname.localshare.service.ktor.routes.getApprovalEvents
import com.defname.localshare.service.ktor.routes.getAssets
import com.defname.localshare.service.ktor.routes.getEvents
import com.defname.localshare.service.ktor.routes.getFavIcon
import com.defname.localshare.service.ktor.routes.getFile
import com.defname.localshare.service.ktor.routes.getFileIcon
import com.defname.localshare.service.ktor.routes.getLanding
import com.defname.localshare.service.ktor.routes.getThumbnail
import com.defname.localshare.service.ktor.routes.getWaiting
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.plugins.partialcontent.PartialContent
import io.ktor.server.request.httpMethod
import io.ktor.server.request.uri
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.IgnoreTrailingSlash
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.configureServerModule(
    serviceRepository: ServiceRepository,
    connectionLogsRepository: ConnectionLogsRepository,
    settingsRepository: SettingsRepository,
    securityHandler: ServerSecurityHandler,
    fileInfoProvider: FileInfoProvider,
    context: Context
) {
    install(PartialContent)
    install(IgnoreTrailingSlash)

    // Monitoring interceptor: logs every connection open and close.
    // SSE connections log their own disconnect reason in EventsRoute's finally block
    // (which runs before this interceptor's finally, so the reason is preserved).
    intercept(ApplicationCallPipeline.Monitoring) {
        val connectionId = connectionLogsRepository.clientConnected(
            method = call.request.httpMethod.value,
            path = call.request.uri,
            clientIp = call.request.local.remoteHost
        )
        call.attributes.put(CallAttributes.connectionId, connectionId)

        try {
            proceed()
        } finally {
            val statusCode = call.response.status()?.value
            val reason: DisconnectReason = if (statusCode != null) {
                DisconnectReason.Expected(statusCode)
            } else {
                DisconnectReason.Unexpected.Unknown
            }
            // clientDisconnected is idempotent — if EventsRoute already closed it, this is a no-op
            connectionLogsRepository.clientDisconnected(connectionId, reason)
        }
    }

    routing {
        // Favicon at root — suppress browser requests, no token needed
        get("/favicon.ico") {
            call.response.header(HttpHeaders.CacheControl, "public, max-age=31536000, immutable")
            call.respond(HttpStatusCode.NoContent)
        }

        getFavIcon(securityHandler, context)
        getThumbnail(securityHandler, serviceRepository, fileInfoProvider, context)
        getFileIcon(securityHandler, context)
        getAssets(securityHandler, context)
        // Events route: no Context needed anymore
        getEvents(securityHandler, serviceRepository, settingsRepository, connectionLogsRepository)
        getFile(securityHandler, serviceRepository, context)
        getWaiting(securityHandler, context)
        getApprovalEvents(securityHandler)
        // Landing last — it's the wildcard catcher for /{token}/
        getLanding(securityHandler, serviceRepository, context)

        // Catch-all 403 for anything not matched
        get("{...}") {
            call.respondText("No Access.", status = HttpStatusCode.Forbidden)
        }
    }
}
