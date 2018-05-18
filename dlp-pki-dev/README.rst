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
    -d '{"csr":"LS0tLS1[...]"}' \
    http://192.168.56.10:8080/certificate | \
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
    http://192.168.56.10:8080/identities | \
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

  curl -s http://192.168.56.10:8080/identity/my_identity


Obtention de certificat pour une personne
-----------------------------------------
Pour obtenir un certificat pour la personne ``my_person`` par exemple, il faut appeler le service |person|_. :

.. |person| replace:: ``person``
.. _person: /person

.. code-block::

  curl -s http://192.168.56.10:8080/person/my_person


Obtention d'une CRL
-------------------
Pour obtenir la crl pour ``AC Infrastructure``, il faut appeler le endpoint |ac_infra|_.

Pour obtenir la crl pour ``AC Personnes``, il faut appeler le endpoint |ac_personnes|_.

.. |ac_infra| replace:: ``/crl/ac_infra``
.. _ac_infra: /crl/ac_infra
.. |ac_personnes| replace:: ``/crl/ac_personnes``
.. _ac_personnes: /crl/ac_personnes

.. code-block::

  curl -s http://192.168.56.10:8080/crl/ac_infra
  curl -s http://192.168.56.10:8080/crl/ac_personnes


Si vous utilisez un navigateur web graphique (Firefox, Chrome), visualisez le résultat en affichant le source de la page obtenue.
