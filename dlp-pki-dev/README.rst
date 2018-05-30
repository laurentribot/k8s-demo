DLP PKI DEV
===========

Obtention d'un certificat à partir d'une csr
--------------------------------------------
A partir du fichier PEM de la csr encodé en base64 (wrappé sur une 1 ligne) :

.. code-block::

  ma_csr.pem | base64 -w 0

Il faut appeler le service |certificate|_. :

.. |certificate| replace:: ``certificate``
.. _certificate: /certificate

.. code-block::

  curl -s -X POST -H "Content-Type: application/json" \
    -d '{"csr":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ3R6Q0NBWjhDQURBd01TNHdMQVlEVlFRREV5VjBjbUZqYTJOdlpYVnlMbVJsZGpRdVkyOWxkWEl1YkdsdQphM2t1Wlc1bFpHbHpMbVp5TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4ems3CjA1aExvVU9sQThwZzRHbENEVnFQbGovS2tDcTNOa3BzazJwa3plTjR3bzFMMGtYQ1UvSUZHbTNpV1FmSnJhN3QKTVNDSnY4WDhGOFNtWmdiRmZaaFpnY05pMHZlblE5cy94Z3I0QjVra1F1ODFWMkdXdm5ucFpzSENKeDFHZ2FTMwp3MGYwcWRJeGtZZURFTWwvZFoxRWlMQlJOSFc3SWIwUmNlRDVNL2RCWjhQSFh6RExDTU95TGtFcC8zSFZwSFRtClRVRm1OS1pSWjg1TFR6bDc0UjFGUVhEWHFwbWg1Qk9FK0o2YXhkdC9NQ3ZJSVNBTHIvMWFRd2M4Z1dEZS9LeXoKemdNM3BCWXEreDNyZUxRbExTZmY2ZVBBQXlRNmZGRjJiQ2xvaW5sMjBDbjYvU1VYcnc0TjQ2Qm5wVXZleGJWMwpsNlNCaXJQVTBrV28rbEFLR3dJREFRQUJvRU13UVFZSktvWklodmNOQVFrT01UUXdNakF3QmdOVkhSRUVLVEFuCmdpVjBjbUZqYTJOdlpYVnlMbVJsZGpRdVkyOWxkWEl1YkdsdWEza3VaVzVsWkdsekxtWnlNQTBHQ1NxR1NJYjMKRFFFQkN3VUFBNElCQVFDMkVaS3M3cWpkRVB2b2tRV2ZYTjQwTE8zYUVHZkNERjlaZ0pjMXpzS25vbTFJYVprZQpEaXVOMUFOcnJ6elBYQ0xQUG8zc1hKOVN4bXlDdmx0NW5DdnpBb0dlYTlDTmcvSk9FWjVKWUNyeUszcElDalh3CmtOQTlDTWZuMWNwTXpUT1VsU3U2NzhVRGluN2hLdXRWSjVFQkV6TTdzNG51OFRMNFFpTWQ3emd5TGRwbVVTdlAKRXBSSTRSOVBYWnN6dVdRcks4Rm8wSkg0dkhWMXdXVHc0MDF2NXoxL0dzQTA2REtZVVdjVHBwR3BpaTl5SnZ3cgpqZmFodHhUeXRwYUcvYmd2cXErTk16U2t4NUlCck1oWGJFTkc2MGRSWlFjSzhYY2dJMTdiNGR5aURnY2t1NEVECkpBbDU5OEJQUWc2WUFRLzEvV2NFVllFV1diQTk1cmR5MUV0UQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K"}' \
    http://dlp-pki-dev.G2N-Linky-Paris.gate-noe.enedis.fr:8080/certificate | \
    jq -r .certificate | \
    base64 -d | \
    openssl x509 -text -noout


Obtention de certificats à partir d'une liste de noms
-----------------------------------------------------
Pour obtenir des certificats pour les identités ``identity1`` et ``identity2``  par exemple, il faut appeler le service |identities|_. :

.. |identities| replace:: ``identities``
.. _identities: /identities

.. code-block::

  curl -s -X POST -H "Content-Type: application/json" \
    -d '{"identities" : ["identity1","identity2"]}' \
    http://dlp-pki-dev.G2N-Linky-Paris.gate-noe.enedis.fr:8080/identities | \
    jq -r '.[] | .certificate' | \
    while read cert; do \
        echo $cert | base64 -d; \
    done


Obtention de certificat pour une identité
-----------------------------------------
Pour obtenir un certificat pour l'identité ``my_identity`` par exemple, il faut appeler le service |identity|_. :

.. |identity| replace:: ``identity``
.. _identity: /identity

.. code-block::

  curl -s http://dlp-pki-dev.G2N-Linky-Paris.gate-noe.enedis.fr:8080/identity/my_identity


Obtention de certificat pour une personne
-----------------------------------------
Pour obtenir un certificat pour la personne ``my_person`` par exemple, il faut appeler le service |person|_. :

.. |person| replace:: ``person``
.. _person: /person

.. code-block::

  curl -s http://dlp-pki-dev.G2N-Linky-Paris.gate-noe.enedis.fr:8080/person/my_person


Obtention d'une CRL
-------------------
Pour obtenir la crl pour ``AC Infrastructure``, il faut appeler le endpoint |ac_infra|_.

Pour obtenir la crl pour ``AC Personnes``, il faut appeler le endpoint |ac_personnes|_.

.. |ac_infra| replace:: ``/crl/ac_infra``
.. _ac_infra: /crl/ac_infra
.. |ac_personnes| replace:: ``/crl/ac_personnes``
.. _ac_personnes: /crl/ac_personnes

.. code-block::

  curl -s http://dlp-pki-dev.G2N-Linky-Paris.gate-noe.enedis.fr:8080/crl/ac_infra
  curl -s http://dlp-pki-dev.G2N-Linky-Paris.gate-noe.enedis.fr:8080/crl/ac_personnes


Si vous utilisez un navigateur web graphique (Firefox, Chrome), visualisez le résultat en affichant le source de la page obtenue.
