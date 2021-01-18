# broker-server
Server software for the WP-Broker API interface

## 1. Introduction
This Broker Service is a simple implementation for the WP-Broker API Interface.

The WP-Broker API interface allows two remote sites to start an new communication channel. The user activates a remote action, which is passed through the Broker Service and rerouted using a preset registration cookie to the user's own location. The user location site can then evaluate the action and determine follow up activity.

## 2. API
Sites using the Broker Service must `register` first. This will set an encrypted cookie containing the user landing page. When the user returns with an `action`, the content of this cookie is used to create a callback redirect URL to fulfill the action. The action contains the encrypted remote URL and a relative path on that remote site.

### 2.1 Registration

#### 2.1.1 Initiation

A site sends a GET request to `<server URL>/register`. This contains the `base` URL and the relative `site` landing page. The `site` entry must be an absolute path, but relative to the `base` entry. The complete URL of the landing page is therefor `<base><site>`. This is specifically done to prevent situations where the `site` is hosted on `domain X` and the `base` is on `domain Y` (cross domain). 
`site` and `base` can be encoded. If so, the encoding algorithm is prepended and separated using a colon (:). The following encoding algorithms MUST be supported:
- b64: base64 encoded text content (when used in a URL it is url encoded to escape the '+','=' and '/' characters)

Example:
Base is at `https://www.example.com`: aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20K  
Site is at `/wp-admin/admin-ajax.php?action=wp-broker&id=2`: L3dwLWFkbWluL2FkbWluLWFqYXgucGhwP2FjdGlvbj13cC1icm9rZXImaWQ9Mgo=  

```url
GET https://www.brokerservice.com/register?base=be64:aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20K&site=b64:L3dwLWFkbWluL2FkbWluLWFqYXgucGhwP2FjdGlvbj13cC1icm9rZXImaWQ9Mgo%3D
```

#### 2.1.2 Validation

As registration is performed by the user, the validity of the content of the variables cannot be checked on the request itself. The Broker Service MAY perform an intermediate validation roundtrip to the site URL to validate that an actual service is active for this user. It will perform an out-of-band call to the `<base><site>` URL with an additional `action=validate` parameter. The user site can check that this service is valid, irrespective of the current session of the user initiating the registration. If the call returns succesfully, the service is valid and else it is not.

This allows third parties to register users with the Broker Service: you do not need to register through the user site to get a cookie pointing to your own service. However, for postbacks to the user site to succeed, a valid session on the user site must be present. This is the difference between 'a service lives here' and 'the service allows using it'. Getting a valid broker service registration cookie is something else than getting a valid user site session cookie.

#### 2.1.3 Final Response

The response on a correct registration sets an encrypted cookie containing the full site URL (`<base><site>`). It also returns the cookie content and the encrypted base URL. The latter value can be used by remote sites to pass to the broker to validate their initial registration:
```
{
    "site": <encrypted content, also set in a cookie>,
    "base": <encrypted content>
}
```
The means of encryption is left to the Broker Service implementation. This is normally done using a privately generated encryption key.

## 3. Action

### 3.1 Action Types

Users can perform several actions on remote sites. Each action is described by a free-form `action` element containing a text describing the actual action performed on the remote content. To limit attack vectors, the `action` string can only contain ASCII alpha-numeric characters, dashes and dots (`[-a-zA-Z0-9.]`). The following `action` suggestions are made:

- `like` for actions indicating a user likes the remote content and supports it (aka: thumbs up)
- `follow`: for actions indicating a user likes the remote content and wants to follow future changes and updates
- `dislike`: for actions indicating the user does not support the remote content or dislikes its meaning
- `lol`: for indicating the user not only likes the remote content, but had a jolly good time consuming it
- `mpty`: More Power To You, indicating the user strongly supports the remote content and is considering participating
- `love`: for indicating the user wishes to send the remote site content author loads of love, get-well-soon-wishes and emotional support or is otherwise emotionally touched by the content
- `validate`: to check that a valid service exists, irrespective of active user sessions (used in the callback validation above)
- `push`: to push the web content to a user site that has previously registered its interest. This is done out-of-band and outside user sessions, so the receiving site must check that the remote content as defined by the `base` parameter was previously accepted as push source.
- `id`: to indicate the remote server wishes to ID (profile) the current visitor based on its origin site.

More suggestions may be added in the future. The course of action to take for each action is completely left to the implementation on the user site. If an `action` is received that is not in the list of recognised actions of the user site, the user site can default to a general action (e.g.: `like`), or disregard the activity.

### 3.2 Remote to Broker

When a user clicks on an actionable element on a remote site, the remote site can create a GET request to the Broker Service containing the encrypted `base` content and a relative URL `site` path to the actual content. The remote site can optionally send the `action` the user performs along with this data.

The remote site can also optionally send a `cb` callback element containing a relative URL path containing callback parameters for the relevant action. In the case of a `follow` action, it would contain a callback where new updates can be retrieved, or where a `push` subscription can be requested.

The relative URL paths can be encoded. If so, the encoding algorithm is prepended and separated using a colon (:). The following encoding algorithms MUST be supported:

- base64 (prefix: 'b64:', if so required, url encoded to escape the '+','=' and '/' characters)

Example:  
Base is a URL safe blob (broker service implementation defined): 6a6d7e7f887a738029918a8098f0a0a00  
Site is at `/my/new/blogpost`: b64:L215L25ldy9ibG9ncG9zdAo=  
Callback is at `/wp-admin/admin-ajax.php?action=wp-broker&id=5&action=follow`: b64:L3dwLWFkbWluL2FkbWluLWFqYXgucGhwP2FjdGlvbj13cC1icm9rZXImaWQ9NSZhY3Rpb249Zm9sbG93Cg==  
Action is `follow`  

```url
GET https://www.brokerservice.com/action?base=6a6d7e7f887a738029918a8098f0a0a00&site=L215L25ldy9ibG9ncG9zdAo%3D&action=follow&cb=L3dwLWFkbWluL2FkbWluLWFqYXgucGhwP2FjdGlvbj13cC1icm9rZXImaWQ9NSZhY3Rpb249Zm9sbG93Cg%3D%3D

```

### 3.3 Processing

The Broker Service parses the request parameters, decodes the base value into the original base URL. It knows the base URL is a previously registered URL. The Broker Service MUST perform additional checks on the site URL and optional callback URL to ensure they remain within the base URL path and domain and do not contain attack vectors. The Broker Service then reads the implementation specific cookie of the user browser and retrieves the encoded landing page URL. It creates a redirection URL to that landing page containing the remote `site` and the optional `action`:

Base URL is `https://www.example.com`: b64:aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20K  
Site path is `/my/new/blogpost`: b64:L215L25ldy9ibG9ncG9zdAo=  
Callback path is `/wp-admin/admin-ajax.php?action=wp-broker&id=5&action=follow`: b64:L3dwLWFkbWluL2FkbWluLWFqYXgucGhwP2FjdGlvbj13cC1icm9rZXImaWQ9NSZhY3Rpb249Zm9sbG93Cg==  
Action is `follow`  

```url
GET https://www.example.com/wp-admin/admin-ajax.php?action=wp-broker&id=2&base=b64:aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20K&site=b64:L215L25ldy9ibG9ncG9zdAo%3D&cb=b64:L3dwLWFkbWluL2FkbWluLWFqYXgucGhwP2FjdGlvbj13cC1icm9rZXImaWQ9NSZhY3Rpb249Zm9sbG93Cg%3D%3D&action=follow
```

When the Broker Service cannot successfully read the user cookie containing the user site callback, the service returns a `403 Forbidden` result. This can have several causes, usually because the user has never registered on that site in this session yet. It could also be caused by a change of the encryption key on the Broker Service or an error in any of the message parameters.

### 3.4 Broker Service to User Site

The user site can then process the action and the remote URL. What it will do with this information is left to the user site implementation. By default it can, for example, store the remote URL, retrieve (part of) the content and display it on the local user wall for other visitors to discover. As this processing is done out-of-band, the user site can simply return a `204 No Content` status code.

Alternatively, the user site may return the actual `action` as stored in its settings. This is normally the same as the `action` indicated by the remote site, but perhaps a translation is made (e.g. from an unknown type to a default type, or from a deprecated type to a later version type). The return object will look like:

```json
{
    "action": <action string>
}
```

For message actions of type `id`, it can decide to return an additional `uuid` value:

```json
{
    "action": "id",
    "uuid": <user site specific uuid for this remote service>
}
```

Allowing the `id` action is an optional functionality of the user site implementation. If profiling in this way is not supported, the user site can return a `403 Forbidden` or another `4XX` error code.

## 4. Callbacks

This protocol is run outside the Broker Service, between two Broker Clients. The following description is therefor a suggestion, but has no implementation in this code base.

If the remote site passes a callback URL, it offers the option of further interaction between the user site and the remote site. Whether the user site will engage in this interaction can be configured by user preferences. The additional interaction takes place out-of-band using server-server communication, using POST messages. Each message contains the following setup:

```json
{
    "action": <message type>,
    // additional message specific content
}
```

Return messages are created using the same setup and same definition. Responses to messages can be either a new message or a regular HTTP response code:

- `200 Ok`: for responses containing messages
- `204 No Content`: for responses without messages, to indicate acceptance
- `401 Unauthorized`: to indicate refusal to process
- `403 Forbidden`: to indicate refusal to process
- `406 Not Acceptable`: to indicate refusal to process

Messages are sent to and from the respective callback URLs provided by the remote site through the Broker Service. Each interaction starts with a single message from the user site and gets a single response from the remote site. The following callback message actions are defined:

- `sub`, where the message contains a full callback URL in a `cb` value. The user site uses this to indicate it wishes to subscribe to updates on the remote site, content or other actionable element and requests the remote site to push updates whenever it wants. This puts the burden of updating on the remote site. The `cb` value is a full callback URL that will allow the remote site to act as a "user site" in the messaging sequence.
- `req`, where the message contains a full callback URL in a `cb` value. The remote site can use this as reply to indicate it will not push new updates, but requests the user site to periodically request new updates using the supplied callback. This puts the burden of updating on the user site. If no `cb` is provided, the `cb` already known to the user site can be used in the future.
- `ping`, where the message contains an `action` value. This is used to indicate to a remote site which `action` was actually performed on content received out-of-band.
- `upd`, with an 'if-modified-since' HTTP header. Requests a list of post links since the indicated time. 
- `upd`, without an if-modified-since header, but with a `content` value in the message. The `content` is an array of objects containing 2 values: `base`, and `site` and an optional `action` and `cb`, with the same implementation as for the regular action sequence above. The receiving site can decide to parse each entry and invoke the optional callback with the indicated action or an action of its choosing (e.g.: `like`) using the `ping` message type. This is not required.
  
`sub` and `req` are meant to be used in dialog: user site sends `sub`, remote site replies with `req` if it does not want to register the `sub`. If the remote site simply accepts the `sub` (indicating it will actively push updates), it can reply with an empty HTTP status 204 (not content) message.

`req` sent as initial message indicates the originating site wants the remote site to actively start calling the supplied callback for updates to the related post. This can have specific use cases, but is generally not a great way to introduce yourself.

`ping` should get a 204 (no content) response. If it receives a `308 Permanently Moved` response, the user site may replace its original callback with the new location. This would allow user sites to follow content on remote sites that change implementation or even domain. If it receives a `4XX` response, the content was probably removed and can be removed from the user site as well. If a `5XX` code is received, it can be marked as a temporary error. 

By performing a `ping` on old content on a regular basis, old entries may be removed automatically if their destination content no longer exists. However, this is at the discretion of the user site.

## 5. Examples

### 5.1 Example 1

1. Alice visits the site of Bob and really likes his new photography blog entry. She clicks on the Like button.
2. Alice's browser creates a callback link to a list of brokers supported by the site of Bob
3. Alice's browser performs a GET request to each of the callbacks in this list, stopping at the first successful reaction
4. The Broker Service will redirect Alice's browser to a callback on the site of Alice
5. Alice's site registers the action and queues a retrieval job to retrieve the remote content for local republishing
6. The callback on the site of Alice returns a 200 status code and the action stops
7. The remote site visually indicates the action (thumbs-up, etc). It can track this status using the remote session cookie, but may not be able to correctly display this status in the future if cookies or sessions are lost
8. Alice's site retrieves the remote content using a server-server call. It parses the content and decides on how to represent it on the wall of Alice
9. Alice's site optionally performs a `ping`-back action to the remote site, if a callback was passed

### 5.2 Example 2

1. Victor visits the site of the local communicipality and wants to follow any updates.
2. Victor clicks the 'follow me' link
3. Victor's browser creates a callback link to a list of brokers supported by the site of the communicipality
4. Victor's browser performs a GET request to each of the callbacks, stopping at the first successful action
5. The Broker Service redirects Victor's browser to a callback on the site of Victor
6. Victor's site registers the action and queues a follow-up job
7. The callback on Victor's site returns a 200 status code and the action stops
8. The remote site visually indicates the action. It can track this status using the remote session cookie, but may not be able to correctly display this status in the future if cookies or sessions are lost
9. Victor's site sends a `sub` request to the remote site callback to automatically get notified of future changes
10. The communicipality replies with a `req` message to indicate it will not send updates, but requests Victor's site to periodically look for updates
11. Victor's site replies with a 204 (no content)
12. Every now and then (daily, weekly, monthly) Victor's site calls the communicipality callback with an `upd` message to get a list of updates. It receives an `upd` response and then processes these updates using the supplied suggested actions.

### 5.3 Example 3

1. Harry visits the site of Peter.
2. As soon as the page is opened, Peter's site causes Harry's browser to perform an `id` action
3. Harry's browser creates a callback link to a list of brokers supported by Peter's site
4. Harry's browser performs a GET request to each of the callbacks, stopping at the first successful action
5. The Broker Service redirects Harry's browser to the site of Harry
6. Harry's site responds with a `id` message if it decides to react to this.
7. Peter's site now knows at least one common broker and can try this broker first in any later activity
8. If the user site responded with an `id` message, it will contain a UUID to identify Harry on Peter's site. However, this value may not be unique on Peter's site nor known by Peter. Authentication based on this action is only possible under specific circumstances (when both broker, user site and DNS are fully trusted).

## 6. Trust Model

Trust is placed in the encryption used by the Broker Service, the specific an exclusive availability of cookies for domains through the browser only and the use and abuse of callback URLs by third parties. Multiple attack vectors for either DDOS attacks or profiling exist and need to be mitigated.

### 6.1 DDOS attacks

- When clicking on an actionable element, the remote site instructs the user browser to start performing a series of GET requests to broker services. This could be abused to initiate a DDOS attack. However, in that case either the DNS service needs to be compromised (redirecting valid Broker Service requests to DDOS target sites) or the remote website scripting code needs to be compromised (supplying a different list of URLs to try). The latter situation can also cause the attacker to inject DDOS scripting code directly, so is of no particular importance for this case. Comprimising DNS servers is also of a risk level that can cause many additional attack vectors that this does not particularly concern this implementation.
- Broker Services redirect users to randomly registered sites. Upon registration, the user can supply his/her own choice of callback URL for the Broker Service to validate. The Broker Service can optionally loop-redirect to validate the current user session. However, if it does not, any user can use the Broker Service to validate a random DDOS target URL. For this to happen though, the site visited by the user needs to be comprimised. It can then register a random URL with a Broker Service on behalf of the current user. Anytime the user then visits another site, the browser may be redirected to the DDOS target URL in the process of finding a common broker. As a site with good intentions can track the Broker Service discovery and filter out failed tries, this can be mitigated to a single DDOS target call per visited site. This should be sufficient to not make this a viable DDOS attack vector.
- Compromised sites can send DDOS target URLs as callback through the Broker Service. As the Broker Service AND the user site both check that the callback target URL is within the domain of the (compromised) site, this can only lead to a few calls to the compromised site itself. This defeats the purpose of a DDOS attack.

### 6.2 Profiling

- Whenever a user visits a site, the site can immediately start a Broker Service discovery protocol. The first successful try leads to a user site URL. However, the call is made inside the user browser and the final redirection URL is not visible to the remote site browser code: it is not possible to discern the final Location header in the redirection sequence inside the HttpRequest or Fetch API interface. 
- When the user site wishes to accept remote login, it can decide to return a `uuid` element in whatever make-up it desires. The remote site should not trust this value as being anything else than 'a name by which the user whishes to be known': it has no validation by itself. The remote site can scope the value using the broker service. In closed environments, with carefully trusted brokers and accepted user sites, the scoped value could be considered enough to authenticate.

### 6.3 Replay Attacks

- URLs caught in the middle can be easily sent for a replay attack. Receiving sites however can simply check that a certain action (like, follow) was already processed before and then discard the resend.
- A replay attack of the `id` feature is mitigated using the `nonce` feature. Receiving sites can check that a certain nonce was already used and then prevent the replay attack. This, however, requires some nonce cache or generation algorithm on the remote site.

### 6.4 Man in the Middle

The Broker Service is a Man in the Middle per definition. If attackers can compromise DNS entries, the Broker Service can easily be replaced

#### 6.4.1 DNS compromise of the Client Computer

In this case all the DNS entries visible by the user are compromised. Possibly the local router was hacked and its DHCP and DNS service replaced. In this case, the attacker can reroute the user to any site it wants and the protocol cannot prevent this. Defeat of this kind of attack should be done using HTTPS, where the user browser can detect that the remote certificate is invalid. As long as HTTPS is used in all communication, the user should get ample warning signals. It is conceivable that the attacker replaces all sites and calls with regular HTTP variants, in which case the attacker can easily capture the username/password of the User Site and attack that directly. This vulnerability would cause bigger issues than a mere compromise of this Broker Service protocol. 

#### 6.4.2 DNS compromise of the Broker Service

In this case the Broker Service can no longer determine the correct hosts for incoming and outgoing traffic. As the Broker Service does not actively perform such calls, but only redirects using the user browser, this has no effect on the system.

#### 6.4.3 DNS compromise of the User Site or Remote Site

In this case either the Remote Site or the User site cannot communicate with the resultant callback URLs. The Remote Site may automatically push content to a compromised server. The User Site may perform callbacks for update or pull requests to a compromised server. In both cases, HTTPS validation should be implemented to allow checking the validity of the remote certificate. Only when the DNS entries and network routing can be fully trusted can HTTP connections be allowed. This would be the case for local development environments, completely locked off networks behind a VPN and/or firewall and other secure zones.

## 7. License

Copyright (C) 2021 Michiel Uitdehaag, muis IT

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
