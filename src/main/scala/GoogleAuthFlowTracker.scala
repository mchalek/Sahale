package com.etsy.sahale

import org.apache.http.client.methods.{ HttpPost, CloseableHttpResponse }
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential
import java.util.concurrent.atomic.AtomicBoolean
import cascading.flow.Flow

object GoogleAuthFlowTracker {
  // When should we refresh our credentials?
  val CREDENTIALS_REFRESH_AGE_SECONDS = 100
}

class GoogleAuthFlowTracker(
  flow: Flow[_],
  runCompleted: AtomicBoolean,
  hostPort: String,
  disableProgressBar: Boolean) extends FlowTracker(flow, runCompleted, hostPort, disableProgressBar) {

  if(this.httpHost.getSchemeName != "https") {
    sys.error(s"Invalisd host ${this.httpHost}: Google Auth is only valid over https!")
  }
  private val credentials = GoogleCredential.getApplicationDefault

  private def getToken: String = {
    if(credentials.getExpiresInSeconds < GoogleAuthFlowTracker.CREDENTIALS_REFRESH_AGE_SECONDS) {
      if(!credentials.refreshToken) {
        FlowTracker.LOG.warn("Could not refresh Google Auth token!")
      }
    }

    credentials.getAccessToken
  }

  override def setAdditionalHeaders(request: HttpPost) {
    request.setHeader("Authorization", s"Bearer ${getToken}")
  }
}
