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
  RFC6749:
  I-D.ietf-ace-oauth-authz:
  I-D.ietf-core-coap-pubsub:
  I-D.palombini-ace-key-groupcomm:

informative:

  I-D.ietf-ace-actors:
  I-D.ietf-ace-dtls-authorize:
  I-D.ietf-ace-oscore-profile:
  I-D.ietf-core-resource-directory:

entity:
        SELF: "[RFC-XXXX]"

--- abstract

This specification defines a profile for authentication and authorization for publishers and subscribers in a pub-sub setting scenario in a constrained environment, using the ACE framework. This profile relies on transport layer or application layer security to authorize the publisher to the broker. Moreover, it relies on application layer security for publisher-broker and subscriber-broker communication.

--- middle

# Introduction

The publisher-subscriber setting allows for devices with limited reachability to communicate via a broker that enables store-and-forward messaging between the devices. The pub-sub scenario using the Constrained Application Protocol (CoAP) is specified in {{I-D.ietf-core-coap-pubsub}}. This document defines a way to authorize nodes in a CoAP pub-sub type of setting, using the ACE framework {{I-D.ietf-ace-oauth-authz}}.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

Readers are expected to be familiar with the terms and concepts
described in {{I-D.ietf-ace-oauth-authz}}, {{I-D.palombini-ace-key-groupcomm}} and {{I-D.ietf-core-coap-pubsub}}. In particular, analogously to {{I-D.ietf-ace-oauth-authz}}, terminology for entities in the architecture such as Client (C), Resource Server (RS), and Authorization Server (AS) is defined in OAuth 2.0 {{RFC6749}} and {{I-D.ietf-ace-actors}}, and terminology for entities such as the Key Distribution Center (KDC) and Dispatcher in {{I-D.palombini-ace-key-groupcomm}}.

# Profile Overview {#overview}

The objective of this document is to specify how to protect a CoAP pub-sub communication, as described in {{I-D.ietf-core-coap-pubsub}}, using {{I-D.palombini-ace-key-groupcomm}}, which itself expands the Ace framework ({{I-D.ietf-ace-oauth-authz}}), and profiles ({{I-D.ietf-ace-dtls-authorize}}, {{I-D.ietf-ace-oscore-profile}}).

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
     +---------(A)----+                  |  +-----(D)------+
     |   +--------------------(B)--------+                 |
     v   v                                                 v     
+------------+             +------------+              +------------+  
|   CoAP     | ----(C)---> |   CoAP     |              |    CoAP    | 
|  Client -  | ----(E)---> |  Server -  |              |  Client -  |
|            |             |            | <----(F)---- |            |  
| Publisher  |             |   Broker   | -----(G)---> | Subscriber | 
+------------+             +------------+              +------------+
~~~~~~~~~~~~~
{: #archi title="Architecture CoAP pubsub with Authorization Servers"}
{: artwork-align="center"}

The RS is the broker, which contains the topic. This node corresponds to the Dispatcher, in {{I-D.palombini-ace-key-groupcomm}}.
The AS1 hosts the policies about the Broker: what endpoints are allowed to Publish on the Broker. The Clients access this node to get write access to the Broker.
The AS2 hosts the policies about the topic: what endpoints are allowed to access what topic. This node represents both the AS and Key Distribution Center roles from {{I-D.palombini-ace-key-groupcomm}}. 

There are four phases, the first three can be done in parallel.

<!-- Jim
 One of the things that I am not currently happy with is that you are looking at AS1 and AS2 as being independent appliers of access control logic without any communication between them.  I think that AS1 needs the ability to give policy to AS2 on a topic after it has been created and before any subscribers get keys.  In the case they are co-resident this is trivial, in other cases it may not be. 

 AS1 and AS2 have in my mind clearly separated functions. There is some coordination involved of course (to gain knowledge of the policies), but I think that how this is dealt with is application specific. For example, there could be some node distributing those (they do not need to talk to each other directly). Added some generic considerations at the end of the section.
-->

1. The Publisher requests publishing access to the Broker at the AS1, and communicates with the Broker to set up security.
2. The Publisher requests access to a specific topic at the AS2
3. The Subscriber requests access to a specific topic at the AS2.
4. The Publisher and the Subscriber securely post to and get publications from the Broker.

This exchange aims at setting up 2 different security associations: on the one hand, the Publisher has a security association with the Broker, to protect the communication and securely authorize the Publisher to publish on a topic (Security Association 1). On the other hand, the Publisher has a security association with the Subscriber, to protect the publication content itself (Security Association 2).
The Security Association 1 is set up using AS1 and a profile of {{I-D.ietf-ace-oauth-authz}}, the Security Association 2 is set up using AS2 and {{I-D.palombini-ace-key-groupcomm}}.

Note that, analogously to the Publisher, the Subscriber can also set up an additional security association with the Broker, using an AS, in the same way the Publisher does with AS1. In this case, only authorized Subscribers would be able to get notifications from the Broker. The overhead would be that each Subscriber should access the AS and get all the information to start a secure exchange with the Broker.

<!-- Jim
 It is not clear to me that your allocation of roles to AS1 and
AS2 I correct.  If you have a second publisher, does it need to talk to both
AS1 and AS2 or just to AS2?  Is this really an AS1 controls creation of topics and AS2 controls publishing and subscribing to topics?  If the publisher loses its membership in the group for any reason, should it be able to publish willy-nilly anyway?  I.e. should AS2 be able to "revoke" the publishers right to publish?

A second publisher would need to talk to both AS1 and AS2. As I intended, AS1 controls who can publish to (or create) a topic on a broker, AS2 more generally controls who can decrypt the content of the publication.
"Losing the membership" can mean "not being able to access (read or write) the content of the publication", in which case AS2 should revoke the node's rights or it can mean "not allowed to publish on the broker" (maybe it is still allowed to subscribe to the topic), in which case AS1 should revoke the node's right. Both revocations are not specified for now.
-->

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

<!-- Jim
  I don't think the picture is correct at the bottom of the section.  You have a Publisher-Subscriber client/client association 

  Both publisher and subscriber are CoAP client, as specified in the pub-sub doc
-->
<!-- Jim
Is there any expectation that the broker should be notified
on a "revocation" of a publisher's right to publish?  (As opposed to the right just expiring.)  There is no need to enforce subscribers right to subscribe since a key roll over means that they are getting gibberish.

Yes, the broker should be notified of revocation. This is not specified here, and I think this is a general topic that the framework should address: no profile deals with revocations so far, as far as I can tell. 
-->

Note that AS1 and AS2 might either be co-resident or be 2 separate physical entities, in which case access control policies must be exchanged between AS1 and AS2, so that they agree on rights for joining nodes about specific topics. How the policies are exchanged is out of scope for this profile.

# coap_pubsub Profile {#profile}

This profile uses {{I-D.palombini-ace-key-groupcomm}}, which expands the ACE framework. This document specifies which exact parameters from {{I-D.palombini-ace-key-groupcomm}} have to be used, and the values for each parameter.

The Publisher and the Subscriber map to the Client in {{I-D.palombini-ace-key-groupcomm}}, the AS2 maps to the AS and to the KDC, the Broker maps to the Dispatcher.

Note that both publishers and subscribers use the same profile, called "coap_pubsub".

## Retrieval of COSE Key for protection of content {#retr-cosekey}

This phase is common to both Publisher and Subscriber. To maintain the generality, the Publisher or Subscriber is referred as Client in this section.

~~~~~~~~~~~
   Client                            Broker             AS2
      | [----- Resource Request ---->] |                 |
      |                                |                 |
      | [<-- AS1, AS2 Information ---] |                 |
      |                                                  |
      | -- Authorization + Key Distribution Request ---> |
      |                                                  |
      | <-- Authorization + Key Distribution Response -- |
      |                                                  |
~~~~~~~~~~~
{: #B title="B: Access request - response"}
{: artwork-align="center"}

Complementary to what is defined in {{I-D.ietf-ace-oauth-authz}} (Section 5.1.1), to determine the AS2 in charge of a topic hosted at the Broker, the Broker MAY send the address of both the AS in charge of the topic back to the Client in the 'AS' parameter in the AS Information, as a response to an Unauthorized Resource Request (Section 5.1.2). An example using CBOR diagnostic notation is given below:

~~~~~~~~~~~
    4.01 Unauthorized
    Content-Format: application/ace+cbor
    {"AS1": "coaps://as1.example.com/token",
     "AS2": "coaps://as2.example.com/pubsubkey"}
~~~~~~~~~~~
{: #AS-info-ex title="AS1, AS2 Information example"}
{: artwork-align="center"}

<!-- Jim
 I don't' think that the returned info on the first request is going to be the same for publishers and subscribers.  Not sure what this should really look like.

 The broker _may_ send this info to both pub and sub, and then the subscriber could just discard the AS it does not need (AS1). Or the sub could know what AS to contact from a different exchange.
-->

Analogously to what is defined in {{I-D.ietf-ace-oauth-authz}}, instead of the initial Unauthorized Resource Request message, the Client MAY look up the desired topic in a resource directory (see {{I-D.ietf-core-resource-directory}}).

<!-- Jim
  I am unsure what you believe is going to be accomplished by doing a RD lookup.  You can get the name of the resource, but it would not necessarily return the AS1, AS2 strings.

  Ok, I guess the same comment applies to https://tools.ietf.org/html/draft-ietf-ace-dtls-authorize-01#section-2 (4th paragraph) ? Otherwise I might have misunderstood that.
-->

After retrieving the AS2 address, the Client sends an Authorization + Key Distribution Request, which is an Authorization Request merged with a Key Distribution Request, as described in {{I-D.palombini-ace-key-groupcomm}}, Sections 3.1 and 4.1. The reason for merging these two messages is that the AS2 is both the AS and the KDC, in this setting, so the Authorization Response and the Post Token message are not necessary. 

More specifically, the Client sends a POST request to the /token endpoint on AS2, that MUST contain in the payload (formatted as a CBOR map):

- the following fields from the Authorization Request (Section 3.1 of {{I-D.palombini-ace-key-groupcomm}}):
  * the grant type set to "client_credentials",
  * OPTIONALLY, if needed, other additional parameters such as "Client_id"
- the following fields from the Key Distribution Request (Section 4.1 of {{I-D.palombini-ace-key-groupcomm}}):
  * the client\_cred parameter containing the Client's public key, if the Client needs to directly send that to the AS2,
  * the scope parameter set to a CBOR array containing the broker's topic as first element and the string "publisher" for publishers and "subscriber" for subscribers as second element
  * the get_pub_keys parameter set to 0x01 if the Client needs to retrieve the public keys of the other pubsub members
  * OPTIONALLY, if needed, the pub_keys_repos parameters

Note that the alg parameter in the client_cred COSE_Key MUST be a signing algorithm, as defined in section 8 of {{RFC8152}}.

Examples of the payload of a Authorization + Key Distribution Request are specified in {{fig-post-as2}} and {{fig-post2-as2}}.

The AS2 verifies that the Client is authorized to access the topic and, if the 'client_cred' parameter is present, stores the public key of the Client.

The AS2 response is an Authorization + Key Distribution Response, see Section 4.2 of {{I-D.palombini-ace-key-groupcomm}}. The payload (formatted as a CBOR map) MUST contain:

<!-- Jim
 why not use the cnf return value for the key?  Also there is no reason to make it a bstr rather than a map. 

 I did not use the cnf because of the following reasoning: the key is not used to authenticate the client (pub or sub) to the rs (broker), it is not a pop-key related to a token (no token). For subs, there are both cnf and key parameter (see {{fig-resp2-as2}}). Also, see the example on https://tools.ietf.org/html/draft-seitz-ace-oauth-authz-00#section-6.5 (token-less exchange).
 OK, Changed to map.
-->
<!-- Jim 
  need to define a signers_keys element which returns all of the signing keys.  Defined as an array of keys.  Return other signers for multiple publishers

  Are you sure this comment should be in this section? To a subscriber, yes, the set of all signers keys are returned (see {{subs-profile}} section: "The AS2 response contains a "cnf" parameter whose value is set to a COSE Key Set, (Section 7 of {{RFC8152}}) i.e. an array of COSE Keys, which contains the public keys of all authorized Publishers..."). If you did mean it for publishers, I don't see why.
-->
- the following fields from the Authorization Response (Section 3.2 of {{I-D.palombini-ace-key-groupcomm}}):
  * profile set to "coap_pubsub"
  * scope parameter (optionally), set to a CBOR array containing the broker's topic as first element and the string "publisher" for publishers and "subscriber" for subscribers as second element
- the following fields from the Key Distribution Response (Section 4.2 of {{I-D.palombini-ace-key-groupcomm}}):
  - "key" parameter including:
    * kty with value 4 (symmetric)
    * alg with value defined by the AS2 (Content Encryption Algorithm)
    * Base IV with value defined by the AS2
    * k with value the symmetric key value
    * OPTIONALLY, kid with an identifier for the key value
  - "pub\_keys", containing the public keys of all authorized signing members, if the "get\_pub\_keys" parameter was present and set to 0x01 in the Authorization + Key Distribution Request

Examples for the response payload are detailed in {{fig-resp-as2}} and {{fig-resp2-as2}}.

# Publisher

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
|  Client -  |             |  Server -  |
|            |             |            |
| Publisher  |             |   Broker   |
+------------+             +------------+
~~~~~~~~~~~
{: #pubsub-1 title="Phase 1: Publisher side"}
{: artwork-align="center"}

This is a combination of two independent phases:

* one is the establishment of a secure connection between Publisher and Broker, using an ACE profile such as DTLS {{I-D.ietf-ace-dtls-authorize}} or OSCOAP {{I-D.ietf-ace-oscore-profile}}. (A)(C)
* the other is the Publisher's retrieval of keying material to protect the publication. (B)

In detail:

(A) corresponds to the Access Token Request and Response between Publisher and Authorization Server to retrieve the Access Token and RS (Broker) Information.
As specified, the Publisher has the role of a CoAP client, the Broker has the role of the CoAP server.

(C) corresponds to the exchange between Publisher and Broker, where the Publisher sends its access token to the Broker and establishes a secure connection with the Broker. Depending on the Information received in (A), this can be for example DTLS handshake, or other protocols. Depending on the application, there may not be the need for this set up phase: for example, if OSCOAP is used directly.

(A) and (C) details are specified in the profile used.

(B) corresponds to the retrieval of the keying material to protect the publication, and uses {{I-D.palombini-ace-key-groupcomm}}. The details are defined in {{retr-cosekey}}.

An example of the payload of an Authorization + Key Distribution Request and corresponding Response for a Subscriber is specified in {{fig-post-as2}} and {{fig-resp-as2}}.

~~~~~~~~~~~~
{
  "grant_type" : "client_credentials",
  "scope" : ["Broker1/Temp", "publisher"],
  "client_id" : "publisher1",
  "client_cred" : 
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
{: #fig-post-as2 title="Authorization + Key Distribution Request payload for a Publisher"}
{: artwork-align="center"}

~~~~~~~~~~~~
{
  "profile" : "coap_pubsub",
  "key" : {1: 4, 2: h'1234', 3: 12, 5: h'1f389d14d17dc7', 
  -1:   h'02e2cc3a9b92855220f255fff1c615bc'}
}
~~~~~~~~~~~~
{: #fig-resp-as2 title="Authorization + Key Distribution Response payload for a Publisher"}
{: artwork-align="center"}



# Subscriber {#subs-profile}

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
                                            +-----(D)------+
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

Step (D) between Subscriber and AS2 corresponds to the retrieval of the keying material to verify the publication.  The details are defined in {{retr-cosekey}}

This step is the same as (B) between Publisher and AS2 ({{retr-cosekey}}), with the following differences:

* The Authorization + Key Distribution Request MUST NOT contain the client\_cred parameter, the role element in the 'scope' parameter MUST be set to "subscriber". The Subscriber MUST have access to the public keys of all the Publishers; this MAY be achieved in the Authorization + Key Distribution Request by using the parameter get_pub_keys set to 0x01.

* The Authorization + Key Distribution Response MUST contain the pub_keys parameter.

An example of the payload of an Authorization + Key Distribution Request and corresponding Response for a Subscriber is specified in {{fig-post2-as2}} and {{fig-resp2-as2}}.

~~~~~~~~~~~~
{
  "grant_type" : "client_credentials",
  "scope" : ["Broker1/Temp", "subscriber"],
  "get_pub_keys" : 0x01
}
~~~~~~~~~~~~
{: #fig-post2-as2 title="Authorization + Key Distribution Request payload for a Subscriber"}
{: artwork-align="center"}

~~~~~~~~~~~~
{
  "profile" : "coap_pubsub",
  "scope" : ["Broker1/Temp", "subscriber"],
  "key" : {1: 4, 2: h'1234', 3: 12, 5: h'1f389d14d17dc7', 
  -1: h'02e2cc3a9b92855220f255fff1c615bc'},
  "pub_keys" : [
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
{: #fig-resp2-as2 title="Authorization + Key Distribution Response payload for a Subscriber"}
{: artwork-align="center"}

# Pub-Sub Protected Communication

<!-- Jim
 Need to talk about how to deal with multiple publishers - are you assigning different keys or are you using different IV sections?
Need to ensure that you don't have an error from using the same key/iv pair.

Right, the key is the same ("key" in previous sections), but the IV is different. Added Base IV in the COSE_Key in previous section, and partial IV in the COSE_Key. Added TODO for sending Partial IV range for each publisher.
-->

<!-- Jim
 Do you want to talk about coordination of the observer number and the iv of a message?

 What do you mean by "observer number"?
-->

This section specifies the communication Publisher-Broker and Subscriber-Broker, after the previous phases have taken place.

~~~~~~~~~~~~       
+------------+             +------------+              +------------+  
|   CoAP     |             |   CoAP     |              |    CoAP    | 
|  Client -  |             |  Server -  |              |  Client -  |
|            | ----(E)---> |            |              |            |  
| Publisher  |             |   Broker   | <----(F)---- | Subscriber | 
|            |             |            | -----(G)---> |            |
+------------+             +------------+              +------------+
~~~~~~~~~~~~~
{: #pubsub-3 title="Phase 3: Secure communication between Publisher and Subscriber"}
{: artwork-align="center"}

The (E) message corresponds to the publication of a topic on the Broker.
The publication (the resource representation) is protected with COSE ({{RFC8152}}).
The (F) message is the subscription of the Subscriber, which is unprotected.
The (G) message is the response from the Broker, where the publication is protected with COSE.

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
{: #E-F-G-ex title="(E), (F), (G): Example of protected communication"}
{: artwork-align="center"}

## Using COSE Objects to protect the resource representation

The Publisher uses the symmetric COSE Key received from AS2 in exchange B ({{retr-cosekey}}) to protect the payload of the PUBLISH operation (Section 4.3 of {{I-D.ietf-core-coap-pubsub}}). Specifically, the COSE Key is used to create a COSE\_Encrypt0 with algorithm specified by AS2. The Publisher uses the private key corresponding to the public key sent to the AS2 in exchange B ({{retr-cosekey}}) to countersign the COSE Object as specified in Section 4.5 of {{RFC8152}}. The CoAP payload is replaced by the COSE object before the publication is sent to the Broker.

The Subscriber uses the kid in the countersignature field in the COSE object to retrieve the right public key to verify the countersignature. It then uses the symmetric key received from AS2 to verify and decrypt the publication received in the payload of the CoAP Notification from the Broker.

The COSE object is constructed in the following way:

* The protected Headers (as described in Section 3 of {{RFC8152}}) MAY contain the kid parameter, with value the kid of the symmetric COSE Key received in {{retr-cosekey}} and MUST contain the content encryption algorithm 
* The unprotected Headers MUST contain the Partial IV and the counter signature that includes:
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

The following registrations are done for the ACE OAuth Profile Registry following the procedure specified in {{I-D.ietf-ace-oauth-authz}}.

Note to RFC Editor: Please replace all occurrences of "\[\[This document\]\]"
with the RFC number of this specification and delete this paragraph.

Name: coap_pubsub

Description: Profile for delegating client authentication and authorization for publishers and subscribers in a pub-sub setting scenario in a constrained environment.

CBOR Key: TBD

Reference: \[\[This document\]\]

--- back

# Acknowledgments
{: numbered="no"}

The author wishes to thank Ari Keränen, John Mattsson, Ludwig Seitz, Göran Selander, Jim Schaad and Marco Tiloca for the useful discussion and reviews that helped shape this document.

--- fluff

<!-- Local Words: -->
<!-- Local Variables: -->
<!-- coding: utf-8 -->
<!-- ispell-local-dictionary: "american" -->
<!-- End: -->
