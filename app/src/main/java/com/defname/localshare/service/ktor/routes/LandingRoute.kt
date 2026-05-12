// SPDX-FileCopyrightText: 2026 2026 defname
//
// SPDX-License-Identifier: GPL-3.0-or-later

package com.defname.localshare.service.ktor.routes

import android.content.Context
import com.defname.localshare.data.ServiceRepository
import com.defname.localshare.service.ServerSecurityHandler
import com.defname.localshare.service.ktor.responses.sendFileListing
import com.defname.localshare.service.ktor.responses.sendZip
import io.ktor.http.Cookie
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.cookies
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import kotlinx.coroutines.flow.first

fun Route.getLanding(
    securityHandler: ServerSecurityHandler,
    serviceRepository: ServiceRepository,
    context: Context
) {
    get("/{token}/") {
        val token = call.parameters["token"]
            ?: return@get call.respondText("No Access.", status = HttpStatusCode.Forbidden)
        val download = call.queryParameters["download"] != null

        when (val access = securityHandler.checkLandingAccess(call)) {
            is ServerSecurityHandler.LandingAccess.Allowed -> {
                val fileList = serviceRepository.fileList.first()
                if (download) {
                    call.sendZip(files = fileList, securityHandler = securityHandler, context = context)
                } else {
                    call.sendFileListing(files = fileList, token = token, context = context)
                }
            }
            is ServerSecurityHandler.LandingAccess.NeedsApproval -> {
                // Set session cookie then redirect to waiting page
                call.response.cookies.append(
                    Cookie(
                        name = "ls_session",
                        value = access.sessionId,
                        path = "/$token",
                        extensions = mapOf("SameSite" to "Strict")
                    )
                )
                call.respondRedirect("/$token/waiting")
            }
            ServerSecurityHandler.LandingAccess.RateLimited -> {
                call.respondText(
                    "Too many failed attempts. Please wait a few minutes.",
                    status = HttpStatusCode.TooManyRequests
                )
            }
            ServerSecurityHandler.LandingAccess.Forbidden -> {
                call.respondText("No Access.", status = HttpStatusCode.Forbidden)
            }
        }
    }

    // "I'm Done" — client revokes its own session
    delete("/{token}/session") {
        val token = call.parameters["token"]
            ?: return@delete call.respondText("No Access.", status = HttpStatusCode.Forbidden)

        if (!securityHandler.checkToken(token)) {
            return@delete call.respondText("No Access.", status = HttpStatusCode.Forbidden)
        }

        val sessionId = call.request.cookies["ls_session"]
        if (sessionId != null) {
            securityHandler.revokeSession(sessionId)
        }

        // Clear the cookie by setting maxAge = 0
        call.response.cookies.append(
            Cookie(name = "ls_session", value = "", path = "/$token", maxAge = 0)
        )
        call.respondText("Session ended.", status = HttpStatusCode.OK)
    }
}
