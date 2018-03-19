# coding: utf-8

"""
    dacat-api

    No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)

    OpenAPI spec version: 2.6.2
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from __future__ import absolute_import

import os
import sys
import unittest

import swagger_client
from swagger_client.rest import ApiException
from swagger_client.apis.access_user_api import AccessUserApi


class TestAccessUserApi(unittest.TestCase):
    """ AccessUserApi unit test stubs """

    def setUp(self):
        self.api = swagger_client.apis.access_user_api.AccessUserApi()

    def tearDown(self):
        pass

    def test_access_user_count(self):
        """
        Test case for access_user_count

        Count instances of the model matched by where from the data source.
        """
        pass

    def test_access_user_create(self):
        """
        Test case for access_user_create

        Create a new instance of the model and persist it into the data source.
        """
        pass

    def test_access_user_create_change_stream_get_access_users_change_stream(self):
        """
        Test case for access_user_create_change_stream_get_access_users_change_stream

        Create a change stream.
        """
        pass

    def test_access_user_create_change_stream_post_access_users_change_stream(self):
        """
        Test case for access_user_create_change_stream_post_access_users_change_stream

        Create a change stream.
        """
        pass

    def test_access_user_delete_by_id(self):
        """
        Test case for access_user_delete_by_id

        Delete a model instance by {{id}} from the data source.
        """
        pass

    def test_access_user_exists_get_access_usersid_exists(self):
        """
        Test case for access_user_exists_get_access_usersid_exists

        Check whether a model instance exists in the data source.
        """
        pass

    def test_access_user_exists_head_access_usersid(self):
        """
        Test case for access_user_exists_head_access_usersid

        Check whether a model instance exists in the data source.
        """
        pass

    def test_access_user_find(self):
        """
        Test case for access_user_find

        Find all instances of the model matched by filter from the data source.
        """
        pass

    def test_access_user_find_by_id(self):
        """
        Test case for access_user_find_by_id

        Find a model instance by {{id}} from the data source.
        """
        pass

    def test_access_user_find_one(self):
        """
        Test case for access_user_find_one

        Find first instance of the model matched by filter from the data source.
        """
        pass

    def test_access_user_patch_or_create(self):
        """
        Test case for access_user_patch_or_create

        Patch an existing model instance or insert a new one into the data source.
        """
        pass

    def test_access_user_prototype_patch_attributes(self):
        """
        Test case for access_user_prototype_patch_attributes

        Patch attributes for a model instance and persist it into the data source.
        """
        pass

    def test_access_user_replace_by_id_post_access_usersid_replace(self):
        """
        Test case for access_user_replace_by_id_post_access_usersid_replace

        Replace attributes for a model instance and persist it into the data source.
        """
        pass

    def test_access_user_replace_by_id_put_access_usersid(self):
        """
        Test case for access_user_replace_by_id_put_access_usersid

        Replace attributes for a model instance and persist it into the data source.
        """
        pass

    def test_access_user_replace_or_create_post_access_users_replace_or_create(self):
        """
        Test case for access_user_replace_or_create_post_access_users_replace_or_create

        Replace an existing model instance or insert a new one into the data source.
        """
        pass

    def test_access_user_replace_or_create_put_access_users(self):
        """
        Test case for access_user_replace_or_create_put_access_users

        Replace an existing model instance or insert a new one into the data source.
        """
        pass

    def test_access_user_update_all(self):
        """
        Test case for access_user_update_all

        Update instances of the model matched by {{where}} from the data source.
        """
        pass

    def test_access_user_upsert_with_where(self):
        """
        Test case for access_user_upsert_with_where

        Update an existing model instance or insert a new one into the data source based on the where criteria.
        """
        pass


if __name__ == '__main__':
    unittest.main()
