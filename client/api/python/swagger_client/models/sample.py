# coding: utf-8

"""
    dacat-api

    No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)

    OpenAPI spec version: 2.6.2
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from pprint import pformat
from six import iteritems
import re


class Sample(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self, samplelId=None, owner=None, description=None, createdAt=None, sampleCharacteristics=None, attachments=None, ownerGroup=None, accessGroups=None, createdBy=None, updatedBy=None, updatedAt=None):
        """
        Sample - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'samplelId': 'str',
            'owner': 'str',
            'description': 'str',
            'createdAt': 'datetime',
            'sampleCharacteristics': 'object',
            'attachments': 'list[str]',
            'ownerGroup': 'str',
            'accessGroups': 'list[str]',
            'createdBy': 'str',
            'updatedBy': 'str',
            'updatedAt': 'datetime'
        }

        self.attribute_map = {
            'samplelId': 'samplelId',
            'owner': 'owner',
            'description': 'description',
            'createdAt': 'createdAt',
            'sampleCharacteristics': 'sampleCharacteristics',
            'attachments': 'attachments',
            'ownerGroup': 'ownerGroup',
            'accessGroups': 'accessGroups',
            'createdBy': 'createdBy',
            'updatedBy': 'updatedBy',
            'updatedAt': 'updatedAt'
        }

        self._samplelId = samplelId
        self._owner = owner
        self._description = description
        self._createdAt = createdAt
        self._sampleCharacteristics = sampleCharacteristics
        self._attachments = attachments
        self._ownerGroup = ownerGroup
        self._accessGroups = accessGroups
        self._createdBy = createdBy
        self._updatedBy = updatedBy
        self._updatedAt = updatedAt

    @property
    def samplelId(self):
        """
        Gets the samplelId of this Sample.

        :return: The samplelId of this Sample.
        :rtype: str
        """
        return self._samplelId

    @samplelId.setter
    def samplelId(self, samplelId):
        """
        Sets the samplelId of this Sample.

        :param samplelId: The samplelId of this Sample.
        :type: str
        """
        if samplelId is None:
            raise ValueError("Invalid value for `samplelId`, must not be `None`")

        self._samplelId = samplelId

    @property
    def owner(self):
        """
        Gets the owner of this Sample.

        :return: The owner of this Sample.
        :rtype: str
        """
        return self._owner

    @owner.setter
    def owner(self, owner):
        """
        Sets the owner of this Sample.

        :param owner: The owner of this Sample.
        :type: str
        """

        self._owner = owner

    @property
    def description(self):
        """
        Gets the description of this Sample.

        :return: The description of this Sample.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this Sample.

        :param description: The description of this Sample.
        :type: str
        """

        self._description = description

    @property
    def createdAt(self):
        """
        Gets the createdAt of this Sample.

        :return: The createdAt of this Sample.
        :rtype: datetime
        """
        return self._createdAt

    @createdAt.setter
    def createdAt(self, createdAt):
        """
        Sets the createdAt of this Sample.

        :param createdAt: The createdAt of this Sample.
        :type: datetime
        """

        self._createdAt = createdAt

    @property
    def sampleCharacteristics(self):
        """
        Gets the sampleCharacteristics of this Sample.

        :return: The sampleCharacteristics of this Sample.
        :rtype: object
        """
        return self._sampleCharacteristics

    @sampleCharacteristics.setter
    def sampleCharacteristics(self, sampleCharacteristics):
        """
        Sets the sampleCharacteristics of this Sample.

        :param sampleCharacteristics: The sampleCharacteristics of this Sample.
        :type: object
        """

        self._sampleCharacteristics = sampleCharacteristics

    @property
    def attachments(self):
        """
        Gets the attachments of this Sample.

        :return: The attachments of this Sample.
        :rtype: list[str]
        """
        return self._attachments

    @attachments.setter
    def attachments(self, attachments):
        """
        Sets the attachments of this Sample.

        :param attachments: The attachments of this Sample.
        :type: list[str]
        """

        self._attachments = attachments

    @property
    def ownerGroup(self):
        """
        Gets the ownerGroup of this Sample.
        Defines the group which owns the data, and therefore has unrestricted access to this data. Usually a pgroup like p12151

        :return: The ownerGroup of this Sample.
        :rtype: str
        """
        return self._ownerGroup

    @ownerGroup.setter
    def ownerGroup(self, ownerGroup):
        """
        Sets the ownerGroup of this Sample.
        Defines the group which owns the data, and therefore has unrestricted access to this data. Usually a pgroup like p12151

        :param ownerGroup: The ownerGroup of this Sample.
        :type: str
        """
        if ownerGroup is None:
            raise ValueError("Invalid value for `ownerGroup`, must not be `None`")

        self._ownerGroup = ownerGroup

    @property
    def accessGroups(self):
        """
        Gets the accessGroups of this Sample.
        Optional additional groups which have read access to the data. Users which are member in one of the groups listed here are allowed to access this data. The special group 'public' makes data available to all users

        :return: The accessGroups of this Sample.
        :rtype: list[str]
        """
        return self._accessGroups

    @accessGroups.setter
    def accessGroups(self, accessGroups):
        """
        Sets the accessGroups of this Sample.
        Optional additional groups which have read access to the data. Users which are member in one of the groups listed here are allowed to access this data. The special group 'public' makes data available to all users

        :param accessGroups: The accessGroups of this Sample.
        :type: list[str]
        """

        self._accessGroups = accessGroups

    @property
    def createdBy(self):
        """
        Gets the createdBy of this Sample.
        Functional or user account name who created this instance

        :return: The createdBy of this Sample.
        :rtype: str
        """
        return self._createdBy

    @createdBy.setter
    def createdBy(self, createdBy):
        """
        Sets the createdBy of this Sample.
        Functional or user account name who created this instance

        :param createdBy: The createdBy of this Sample.
        :type: str
        """

        self._createdBy = createdBy

    @property
    def updatedBy(self):
        """
        Gets the updatedBy of this Sample.
        Functional or user account name who last updated this instance

        :return: The updatedBy of this Sample.
        :rtype: str
        """
        return self._updatedBy

    @updatedBy.setter
    def updatedBy(self, updatedBy):
        """
        Sets the updatedBy of this Sample.
        Functional or user account name who last updated this instance

        :param updatedBy: The updatedBy of this Sample.
        :type: str
        """

        self._updatedBy = updatedBy

    @property
    def updatedAt(self):
        """
        Gets the updatedAt of this Sample.

        :return: The updatedAt of this Sample.
        :rtype: datetime
        """
        return self._updatedAt

    @updatedAt.setter
    def updatedAt(self, updatedAt):
        """
        Sets the updatedAt of this Sample.

        :param updatedAt: The updatedAt of this Sample.
        :type: datetime
        """

        self._updatedAt = updatedAt

    def to_dict(self):
        """
        Returns the model properties as a dict
        """
        result = {}

        for attr, _ in iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """
        Returns the string representation of the model
        """
        return pformat(self.to_dict())

    def __repr__(self):
        """
        For `print` and `pprint`
        """
        return self.to_str()

    def __eq__(self, other):
        """
        Returns true if both objects are equal
        """
        if not isinstance(other, Sample):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """
        Returns true if both objects are not equal
        """
        return not self == other
