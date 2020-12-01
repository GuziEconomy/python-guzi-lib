from guzilib.crypto import zip_positions, unzip_positions


class TestZipPositions:
    def test_zip_empty(self):
        unzipped = []
        expected = []

        result = zip_positions(unzipped)

        assert result == expected

    def test_zip_positions_empty(self):
        unzipped = [("2020-12-22",0)]
        expected = [(['2020-12-22'], [0])]

        result = zip_positions(unzipped)

        assert result == expected

    def test_zip_positions_less_than_5(self):
        unzipped = [("2020-12-22",0),("2020-12-22",1),("2020-12-22",2),("2020-12-22",3),("2020-12-22",4)]
        expected = [(['2020-12-22'], [0, 1, 2, 3, 4])]

        result = zip_positions(unzipped)

        assert result == expected

    # TODO
    #def test_zip_positions_more_than_5(self):
    #    unzipped = [("2020-12-22",0),("2020-12-22",1),("2020-12-22",2),("2020-12-22",3),("2020-12-22",4), ("2020-12-22",5)]
    #    expected = [(['2020-12-22'], [0, "to", 5])]

    #    result = zip_positions(unzipped)

    #    assert result == expected

    #def test_zip_positions_more_than_5(self):
    #    unzipped = [("2020-12-22",0),("2020-12-23",0),("2020-12-24",0)]
    #    expected = [(['2020-12-22','to','2020-12-24'], [0])]

    #    result = zip_positions(unzipped)

    #    assert result == expected
    
    def test_zip_positions_dates(self):
        unzipped = [("2020-12-22",0),("2020-12-23",0),("2020-12-24",0)]
        expected = [(['2020-12-22','2020-12-23','2020-12-24'], [0])]

        result = zip_positions(unzipped)

        assert result == expected
    
    def test_zip_positions_only_when_possible(self):
        unzipped = [("2020-12-22",0),("2020-12-23",0),("2020-12-23",1),("2020-12-24",0)]
        expected = [(['2020-12-22'], [0]),(['2020-12-23'], [0, 1]),(['2020-12-24'], [0])]

        result = zip_positions(unzipped)

        assert result == expected


class TestUnzipPositions:

    def test_empty_case(self):
        zipped = []
        expected = []

        result = unzip_positions(zipped)

        assert result == expected

    def test_base_case(self):
        zipped = [(['2020-12-22'], [0])]
        expected = [("2020-12-22",0)]

        result = unzip_positions(zipped)

        assert result == expected

    def test_real_case(self):
        zipped = [(['2020-12-22'], [0]),(['2020-12-23'], [0, 1]),(['2020-12-24'], [0])]
        expected = [("2020-12-22",0),("2020-12-23",0),("2020-12-23",1),("2020-12-24",0)]

        result = unzip_positions(zipped)

        assert result == expected

    def test_result_is_date_ordered(self):
        zipped = [(['2020-12-24'], [0]),(['2020-12-23'], [0, 1]),(['2020-12-22'], [0])]
        expected = [("2020-12-22",0),("2020-12-23",0),("2020-12-23",1),("2020-12-24",0)]

        result = unzip_positions(zipped)

        assert result == expected
