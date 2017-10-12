---
coding: utf-8

title: CoAP Pub-Sub Profile for Authentication and Authorization for Constrained Environments (ACE)
abbrev: coap-pubsub-profile
docname: draft-palombini-ace-coap-pubsub-profile-latest
#date: 2017-03-13
category: std

ipr: trust200902
area: Security
workgroup: ACE Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: F. Palombini
    name: Francesca Palombini
    org: Ericsson
    email: francesca.palombini@ericsson.com


normative:

  RFC8152:
  RFC2119:
  I-D.ietf-ace-oauth-authz:
  I-D.ietf-core-coap-pubsub:

informative:

  I-D.seitz-ace-oauth-authz:
  I-D.gerdes-ace-dtls-authorize:
  I-D.seitz-ace-oscoap-profile:
  I-D.ietf-core-resource-directory:

entity:
        SELF: "[RFC-XXXX]"

--- abstract

This specification defines a profile for authentication and authorization for publishers and subscribers in a pub-sub setting scenario in a constrained environment, using the ACE framework. This profile relies on transport layer or application layer security to authorize the publisher to the broker. Moreover, it relies on application layer security for publisher-broker and subscriber-broker communication.

--- middle

# Introduction

This specification defines a way to authorize nodes in a CoAP pub-sub type of setting, using the ACE framework {{I-D.ietf-ace-oauth-authz}}. The pub-sub scenario is described in {{I-D.ietf-core-coap-pubsub}}. 

<!-- I think you should give a (very) brief introduction into the pub sub system here rather than assuming that people are going to read the pub/sub draft first. -->

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

Readers are expected to be familiar with the terms and concepts
described in {{I-D.ietf-ace-oauth-authz}} and {{I-D.ietf-core-coap-pubsub}}.

# Overview {#overview}

<!-- I have a slight problem with the title of this section.  To me I would expect an "Overview" and an "Introduction" to be the same section.  Think about combining the sections together or rename this section to be more specific. -->

The objective of this specification is to specify how to protect a CoAP pub-sub communication, as described in {{I-D.ietf-core-coap-pubsub}}, using Ace framework ({{I-D.ietf-ace-oauth-authz}}) and profiles ({{I-D.gerdes-ace-dtls-authorize}}, {{I-D.seitz-ace-oscoap-profile}}).

The architecture of the scenario is shown in {{archi}}.

~~~~~~~~~~~~       
             +----------------+   +----------------+
             |                |   |                |
             | Authorization  |   | Authorization  |
             |    Server 1    |   |    Server 2    |
             |                |   |                |
             +----------------+   +----------------+
                      ^                  ^  ^
                      |                  |  |
     +---------(A)----+                  |  +-----(E)------+
     |   +--------------------(B)--------+                 |
     v   v                                                 v     
+------------+             +------------+              +------------+  
|   CoAP     | ----(C)---> |   CoAP     |              |    CoAP    | 
|  Client -  | [<--(D)-->] |  Server -  |              |  Client -  |
|            | ----(F)---> |            |              |            |  
| Publisher  |             |   Broker   | <----(G)---- | Subscriber | 
|            |             |            | -----(H)---> |            |
+------------+             +------------+              +------------+
~~~~~~~~~~~~~
{: #archi title="Architecture CoAP pubsub with Authorization Servers"}
{: artwork-align="center"}

The RS is the broker, which contains the topic.
The AS1 hosts the policies about the Broker: what endpoints are allowed to Publish on the Broker.
The AS2 hosts the policies about the topic: what endpoints are allowed to access what topic.
There are four phases, the first three can be done in parallel.

<!-- You need to expand and define RS and AS on first usage.-->
<!-- One of the things that I am not currently happy with is that you are looking at AS1 and AS2 as being independent appliers of access control logic without any communication between them.  I think that AS1 needs the ability to give policy to AS2 on a topic after it has been created and before any subscribers get keys.  In the case they are co-resident this is trivial, in other cases it may not be. -->

1. The Publisher requests publishing access to a broker at the AS1, and communicates with the Broker to set up security.
2. The Publisher requests access to a specific topic at the AS2
3. The Subscriber requests access to a specific topic at the AS2.
4. The Publisher and the Subscriber securely post to and get publications from the Broker.

This scenario requires the setup of 2 different security associations: on the one hand, the Publisher has a security association with the Broker, to protect the communication and securely authorize the Publisher to publish on a topic (Security Association 1). On the other hand, the Publisher has a security association with the Subscriber, to protect the publication content itself (Security Association 2).
The Security Association 1 is set up using AS1, the Security Association 2 is set up using AS2.

<!-- this is a nit - I think that you want a different term than scenario here. -->
<!-- It is not clear to me that your allocation of roles to AS1 and
AS2 I correct.  If you have a second publisher, does it need to talk to both
AS1 and AS2 or just to AS2?  Is this really an AS1 controls creation of topics and AS2 controls publishing and subscribing to topics?  If the publisher loses its membership in the group for any reason, should it be able to publish willy-nilly anyway?  I.e. should AS2 be able to "revoke" the publishers right to publish? -->

~~~~~~~~~~~~         
+------------+             +------------+              +------------+  
|   CoAP     |             |   CoAP     |              |    CoAP    | 
|  Client -  |             |  Server -  |              |  Client -  |
|            |             |            |              |            |  
| Publisher  |             |   Broker   |              | Subscriber | 
+------------+             +------------+              +------------+
      :   :                       :                           :
      :   '------ Security -------'                           :
      :         Association 1                                 :
      '------------------------------- Security --------------'
                                     Association 2
~~~~~~~~~~~~~

<!-- I don't think the picture is correct at the bottom of the section.  You have a Publisher-Subscriber client/client association -->
<!-- Is there any expectation that the broker should be notified
on a "revocation" of a publisher's right to publish?  (As opposed to the right just expiring.)  There is no need to enforce subscribers right to subscribe since a key roll over means that they are getting gibberish. -->

# Publisher Profile

In this section, it is specified how the Publisher requests, obtains and communicates to the Broker the access token, as well as the retrieval of the keying material to protect the publication.

~~~~~~~~~~~
             +----------------+   +----------------+
             |                |   |                |
             | Authorization  |   | Authorization  |
             |    Server 1    |   |    Server 2    |
             |                |   |                |
             +----------------+   +----------------+
                      ^                  ^
                      |                  |
     +---------(A)----+                  | 
     |   +--------------------(B)--------+ 
     v   v                                                       
+------------+             +------------+ 
|   CoAP     | ----(C)---> |   CoAP     | 
|  Client -  | [<--(D)-->] |  Server -  |
|            |             |            |
| Publisher  |             |   Broker   |
|            |             |            |
+------------+             +------------+
~~~~~~~~~~~
{: #pubsub-1 title="Phase 1: Publisher side"}
{: artwork-align="center"}

<!-- I would remove 'D' from the picture as it gets a confusion between updating the tokens and publishing content.  It is covered just fine by the core document.  If you are using it as a 'publish' operation, then it does not belong in the first bullet point.  It could also be the difference between pushing the token and getting a session.  Again I don't think these need to be separate, that is clear from the core document and you are not doing anything different. -->

This is a combination of two independent phases:

* one is the establishment of a secure connection between Publisher and Broker, using an ACE profile such as DTLS {{I-D.gerdes-ace-dtls-authorize}} or OSCOAP {{I-D.seitz-ace-oscoap-profile}}. (A)(C)(D)
* the other is the Publisher's retrieval of keying material to protect the publication. (B)

In detail:

(A) corresponds to the Access Token Request and Response between Publisher and Authorization Server to retrieve the Access Token and RS (Broker) Information.
As specified, the Publisher has the role of a CoAP client, the Broker has the role of the CoAP server.

(C) corresponds to the exchange between Publisher and Broker, where the Publisher sends its access token to the Broker.

(D) corresponds to the exchange where the Publisher establishes a secure connection with the Broker. Depending on the Information received in (A), this can be for example DTLS handshake, or other protocols such as EDHOC. Depending on the application, there may not be the need for this set up phase: for example, if OSCOAP is used directly and not without EDHOC first.

(A), (C) and (D) details are specified in the profile used.

(B) corresponds to the retrieval of the keying material to protect the publication. The detailed message flow is defined below.

## Retrieval of COSE Key for protection of content {#retr-cosekey}

This phase is common to both Publisher and Subscriber. To maintain the generality, the Publisher or Subscriber is referred as Client in this section.

<!-- I don't' think that the returned info on the first request is going to be the same for publishers and subscribers.  Not sure what this should really look like. -->

~~~~~~~~~~~
   Client                            Broker             AS2
      | [----- Resource Request ---->] |                 |
      |                                |                 |
      | [<-- AS1, AS2 Information ---] |                 |
      |                                                  |
      | ------- Topic Keying Material Request ---------> |
      |                                                  |
      | <------------ Keying Material ------------------ |
      |                                                  |
~~~~~~~~~~~
{: #B title="B: Access request - response"}
{: artwork-align="center"}

Complementary to what is defined in the DTLS profile (section 2.), to determine the AS2 in charge of a topic hosted at the broker, the Broker MAY send the address of both the AS in charge of the topic back to the Client, as a response to a Resource Request (Section 2.1).

<!-- I am unsure what you believe is going to be accomplished by doing a RD lookup.  You can get the name of the resource, but it would not necessarily return the AS1, AS2 strings. -->

Analogously to the DTLS profile, instead of the initial Unauthorized Resource Request message, the Client MAY look up the desired topic in a resource directory (see {{I-D.ietf-core-resource-directory}}).

After retrieving the AS2 address, the Client sends a Topic Keying Material Request, which is a token-less authorization as described in {{I-D.seitz-ace-oauth-authz}}, section 6.5. More specifically, the Client sends a POST request to the /token endpoint on AS2, that MUST contain in the payload:

* the grant type set to "client_credentials",
* the audience parameter set to the Broker,
* the scope parameter set to the topic, 
* the cnf parameter containing the Client's COSE key, if the Client is a publisher, and
* OPTIONALLY, other additional parameters such as the client id or the algorithm.

<!-- I am not sure that it makes any sense to set an audience.
If the scope is the topic then all information exists.  The audience really the subscriber. -->

Note that, if present, the algorithm MUST be a Content Encryption Algorithm, as defined in Section 10 of {{RFC8152}}.
An example of the payload of a Topic Keying Material Request for a Publisher is specified in {{fig-post-as2}}.

~~~~~~~~~~~~
{
  "grant_type" : "client_credentials",
  "aud" : "Broker1",
  "scope" : "Temp",
  "client_id" : "publisher1",
  "cnf" : 
    { / COSE_Key /
      / type / 1 : 2, / EC2 /
      / kid / 2 : h'11',
      / alg / 3 : -7, / ECDSA with SHA-256 /
      / crv / -1 : 1 , / P-256 /
      / x / -2 : h'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de1
      08de439c08551d', 
      / y /-3 : h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e
      9eecd0084d19c' 
    }
}
~~~~~~~~~~~~
{: #fig-post-as2 title="Example of Topic Keying Material Request payload for a Publisher"}
{: artwork-align="center"}

The AS2 verifies that the Client is authorized to access the topic and, if the "cnf" parameter is present, stores the public key of the Client.

<!-- On the unauthorized response, I think you want to be returning different responses to subscriber vs the broker.  A subscriber does not need to know about AS1.  Also I think you should be using the same tag as the base profile for at least one of them - probably the first one you would contact. -->

The AS2 response contains an empty token and the keying material to protect the publication ("key" field in the payload). Moreover, the payload MUST contain the "profile" parameter, set to value "publisher", and the "token_type" set to "none".

<!--why not use the cnf return value for the key?  Also there is no reason to make it a bstr rather than a map. -->
<!-- need to define a signers_keys element which returns all of the signing keys.  Defined as an array of keys.  Return other signers for multiple publishers-->

TODO: define "key" parameter following ACE framework

The "key" parameter value MUST be a serialized COSE Key (see Section 7 of {{RFC8152}}), with the following values:

* kty with value 4 (symmetric)
* alg with value defined by the AS2 (Content Encryption Algorithm)
* k with value the symmetric key value
* OPTIONALLY, kid with an identifier for the key value

<!-- You state that the algorithm must be a CE algorithm, but I think you mean a signing algorithm. -->

An example for the response is detailed in {{fig-resp-as2}}.

~~~~~~~~~~~~
{
  "access_token" : NULL,
  "token_type" : "none",
  "profile" : "publisher",
  "key" : h'a4010402421234030c205002e2cc3a9b92855220f255fff1c615bc'
 /{1: 4, 2: h'1234', 3: 12, -1: h'02e2cc3a9b92855220f255fff1c615bc'}/
}
~~~~~~~~~~~~
{: #fig-resp-as2 title="Example of Topic Keying Material response payload for a Publisher"}
{: artwork-align="center"}

## AS1, AS2 Information

The Client MUST be able to process the following response message from the Broker, in order to retrieve the correct AS1 and AS2 addresses.

This CoAP message MUST have the following characteristics: the CoAP Code MUST be 4.01 "Unauthorized", the payload MUST be present and MUST include the full URI of both AS. An example using CBOR diagnostic notation is given below:

~~~~~~~~~~~
    4.01 Unauthorized
    Content-Format: application/ace+cbor
    {"AS1": "coaps://as1.example.com/token",
     "AS2": "coaps://as2.example.com/pubsubkey"}
~~~~~~~~~~~
{: #AS-info-ex title="AS1, AS2 Information example"}
{: artwork-align="center"}

# Subscriber Profile

In this section, it is specified how the Subscriber retrieves the keying material to protect the publication.

~~~~~~~~~~~
                                  +----------------+
                                  |                |
                                  | Authorization  |
                                  |    Server 2    |
                                  |                |
                                  +----------------+
                                            ^
                                            |
                                            +-----(E)------+
                                                           |
                                                           v     
                                                       +------------+  
                                                       |    CoAP    | 
                                                       |  Client -  |
                                                       |            |  
                                                       | Subscriber | 
                                                       |            |
                                                       +------------+
~~~~~~~~~~~~~
{: #pubsub-2 title="Phase 2: Subscriber side"}
{: artwork-align="center"}

Step (E) between Subscriber and AS2 corresponds to the retrieval of the keying material to verify the publication, and is the same as (B) between Publisher and AS2 ({{retr-cosekey}}), with the following differences:

* The POST request to the /token endpoint on AS2, does not contain the cnf parameter containing the Client's COSE key.

* The AS2 response contains a "cnf" parameter whose value is set to a COSE Key Set, (Section 7 of {{RFC8152}}) i.e. an array of COSE Keys, which contains the public keys of all authorized Publishers, and the "profile" parameter is set to value "subscriber"

An example of the payload of a Topic Keying Material Request and corresponding response for a Subscriber is specified in {{fig-post2-as2}} and {{fig-resp2-as2}}.

~~~~~~~~~~~~
{
  "grant_type" : "client_credentials",
  "aud" : "Broker1",
  "scope" : "Temp",
  "client_id" : "subscriber1"
}
~~~~~~~~~~~~
{: #fig-post2-as2 title="Example of Topic Keying Material Request payload for a Subscriber"}
{: artwork-align="center"}

~~~~~~~~~~~~
{
  "access_token" : NULL,
  "token_type" : "none",
  "profile" : "subscriber",
  "key" : h'a4010402421234030c205002e2cc3a9b92855220f255fff1c615bc',
 /{1: 4, 2: h'1234', 3: 12, -1: h'02e2cc3a9b92855220f255fff1c615bc'}/
  "cnf" : [
   {
      1 : 2, / type EC2 /
      2 : h'11', / kid /
      3 : -7, / alg ECDSA with SHA-256 /
      -1 : 1 , / crv P-256 /
      -2 : h'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de43
      9c08551d', / x /
      -3 : h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd
      0084d19c' / y /
    }
  ]
}
~~~~~~~~~~~~
{: #fig-resp2-as2 title="Example of Topic Keying Material response payload for a Subscriber"}
{: artwork-align="center"}

<!-- see above about strings to be returned here. -->

# Pub-Sub Protected Communication

<!-- Need to talk about how to deal with multiple publishers - are you assigning different keys or are you using different IV sections?
Need to ensure that you don't have an error from using the same key/iv pair. -->

<!-- Are you containing a coap payload or a complete coap message in the payload.  -->

<!-- Do you want to talk about coordination of the observer number and the iv of a message? -->

This section specifies the communication Publisher-Broker and Subscriber-Broker, after the previous phases have taken place.

~~~~~~~~~~~~       
+------------+             +------------+              +------------+  
|   CoAP     |             |   CoAP     |              |    CoAP    | 
|  Client -  |             |  Server -  |              |  Client -  |
|            | ----(F)---> |            |              |            |  
| Publisher  |             |   Broker   | <----(G)---- | Subscriber | 
|            |             |            | -----(H)---> |            |
+------------+             +------------+              +------------+
~~~~~~~~~~~~~
{: #pubsub-3 title="Phase 3: Secure communication between Publisher and Subscriber"}
{: artwork-align="center"}

The (F) message corresponds to the publication of a topic on the Broker.
The publication (the resource representation) is protected with COSE ({{RFC8152}}).
The (G) message is the subscription of the Subscriber, which is unprotected.
The (H) message is the response from the Broker, where the publication is protected with COSE.

The flow graph is presented below.

~~~~~~~~~~~
  Publisher                Broker               Subscriber
      | --- PUT /topic ----> |                       |
      |  protected with COSE |                       |
      |                      | <--- GET /topic ----- |
      |                      |                       |
      |                      | ---- response ------> |
      |                      |  protected with COSE  |
~~~~~~~~~~~
{: #E-F-G-ex title="(F), (G), (H): Example of protected communication"}
{: artwork-align="center"}

## Using COSE Objects to protect the resource representation

The Publisher uses the symmetric COSE Key received from AS2 in exchange B ({{retr-cosekey}}) to protect the payload of the PUBLISH operation (Section 4.3 of {{I-D.ietf-core-coap-pubsub}}). Specifically, the COSE Key is used to create a COSE\_Encrypt0 with algorithm specified by AS2. The Publisher uses the private key corresponding to the public key sent to the AS2 in exchange B ({{retr-cosekey}}) to countersign the COSE Object as specified in Section 4.5 of {{RFC8152}}. The CoAP payload is replaced by the COSE object before the publication is sent to the Broker.

The Subscriber uses the kid in the countersignature field in the COSE object to retrieve the right public key to verify the countersignature. It then uses the symmetric key received from AS2 to verify and decrypt the publication received in the payload of the CoAP Notification from the Broker.

The COSE object is constructed in the following way:

* The protected Headers (as described in Section 3 of {{RFC8152}}) MAY contain the kid parameter, with value the kid of the symmetric COSE Key received in {{retr-cosekey}} and MUST contain the content encryption algorithm 
* The unprotected Headers MUST contain the IV and the counter signature that includes:
  - the algorithm (same value as in the asymmetric COSE Key received in (B)) in the protected header
  - the kid (same value as the kid of the asymmetric COSE Key received in (B)) in the unprotected header
  - the signature computed as specified in Section 4.5 of {{RFC8152}}
* The ciphertext, computed over the plaintext that MUST contain the CoAP payload.

The external_aad, when using AEAD, is an empty string.

An example is given in {{fig-cose-ex}}

~~~~~~~~~~~~
16(
  [
    / protected / h'a2010c04421234' / {
        \ alg \ 1:12, \ AES-CCM-64-64-128 \
        \ kid \ 4: h'1234'
      } / , 
    / unprotected / {
      / iv / 5:h'89f52f65a1c580',
      / countersign / 7:[
        / protected / h'a10126' / {
          \ alg \ 1:-7
        } / , 
        / unprotected / {
          / kid / 4:h'11'
        }, 
        / signature / SIG / 64 bytes signature /
      ]
    }, 
    / ciphertext / h'8df0a3b62fccff37aa313c8020e971f8aC8d'
  ]
)
~~~~~~~~~~~~
{: #fig-cose-ex title="Example of COSE Object sent in the payload of a PUBLISH operation"}
{: artwork-align="center"}

The encryption and decryption operations are described in sections 5.3 and 5.4 of {{RFC8152}}.

# Security Considerations

In the profile described above, the Publisher and Subscriber use asymmetric crypto, which would make the message exchange quite heavy for small constrained devices. Moreover, all Subscribers must be able to access the public keys of all the Publishers to a specific topic to be able to verify the publications. Such a database could be set up and managed by the same entity having control of the topic, i.e. AS2.

An application where it is not critical that only authorized Publishers can publish on a topic may decide not to make use of the asymmetric crypto and only use symmetric encryption/MAC to confidentiality and integrity protect the publication, but this is not recommended since, as a result, any authorized Subscribers with access to the Broker may forge unauthorized publications without being detected. In this symmetric case the Subscribers would only need one symmetric key per topic, and would not need to know any information about the Publishers, that can be anonymous to it and the Broker.

Subscribers can be excluded from future publications through re-keying for a certain topic. This could be set up to happen on a regular basis, for certain applications. How this could be done is out of scope for this work.

The Broker is only trusted with verifying that the Publisher is authorized to publish, but is not trusted with the publications itself, which it cannot read nor modify. In this setting, caching of publications on the Broker is still allowed.

TODO: expand on security and Privacy considerations

# IANA Considerations

TODO: "key" parameter, "publisher" and "subscriber" profile identifiers

# Acknowledgments

The author wishes to thank John Mattsson, Ludwig Seitz and Göran Selander for the useful discussion that helped shape this document.

--- back

<!-- Local Words: -->
<!-- Local Variables: -->
<!-- coding: utf-8 -->
<!-- ispell-local-dictionary: "american" -->
<!-- End: -->
