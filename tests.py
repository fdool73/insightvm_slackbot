import queue
import unittest

import helpers


class ExtractIPsTest(unittest.TestCase):

    def testIPRegexValidIp(self):
        self.assertListEqual(helpers.extract_ips('192.168.1.1'), ['192.168.1.1'])

    def testIPRegexInvalidIp(self):
        self.assertListEqual(helpers.extract_ips('192.168.1.321'), [])

    def testIPRegexOtherString(self):
        self.assertListEqual(helpers.extract_ips('test string'), [])


class ExtractHostnamesTest(unittest.TestCase):

    def testHostnameRegexValidHostname(self):
        self.assertListEqual(helpers.extract_hostnames('some.domain.com'), ['some.domain.com'])

    def testHostnameRegexInvalidHostname(self):
        self.assertListEqual(helpers.extract_hostnames('some.domain..something'), [])

    def testHostnameRegexOtherString(self):
        self.assertListEqual(helpers.extract_hostnames('test string'), [])


class GifTest(unittest.TestCase):

    def testGif(self):
        self.assertIsInstance(helpers.get_gif(), str)


class ParseCommandTest(unittest.TestCase):

    invalid_event = [{
        'type': 'desktop_notification',
        'title': 'Rackspace',
        'subtitle': 'nexpose_bot_test',
        'msg': '1526665992.000620',
        'content': 'Trevor Steen: @InsightVM Scan Bot scan something',
        'channel': 'G45GSCYUU',
        'launchUri': 'slack://channel?id=G45GSCYUU&message=1526665992000620&team=T07TWTBTP',
        'avatarImage': 'https://avatars.slack-edge.com/2017-09-20/244129942242_667f71f5c2f21de1be4d_192.png',
        'ssbFilename': 'knock_brush.mp3',
        'imageUri': None,
        'is_shared': False,
        'event_ts': '1526665992.000777'}]

    valid_event = [{
        'type': 'message',
        'channel': 'G45GSCYUU',
        'user': 'U12181NPK',
        'text': '<@U94L9361Z> scan something',
        'ts': '1526665992.000620',
        'source_team': 'T07TWTBTP',
        'team': 'T07TWTBTP'}]

    def testValidEvent(self):
        message, channel, user = helpers.parse_bot_commands(self.valid_event,
                                                            'U94L9361Z')
        self.assertIsInstance(message, str)
        self.assertIsInstance(channel, str)
        self.assertIsInstance(user, str)

    def testInvalidEvent(self):
        message, channel, user = helpers.parse_bot_commands(self.invalid_event,
                                                            'U12181NPK')
        self.assertIsNone(message)
        self.assertIsNone(channel)
        self.assertIsNone(user)


class DirectMentionTest(unittest.TestCase):

    def testDirectMention(self):
        text = '<@U94L9361Z> scan something'
        user_id, message = helpers.parse_direct_mention(text)
        self.assertEqual(user_id, 'U94L9361Z')
        self.assertEqual(message, 'scan something')

    def testNotDirectMention(self):
        text = 'some random test text'
        user_id, message = helpers.parse_direct_mention(text)
        self.assertEqual(user_id, None)
        self.assertEqual(message, None)


class HandleCommandTest(unittest.TestCase):
    dummy_queue = queue.Queue()

    def testTooManyHosts(self):
        command = 'scan 1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 5.5.5.5 6.6.6.6'
        channel = 'channel_id_string'
        user = 'user_id_string'
        queue = self.dummy_queue

        response = helpers.handle_command(command, channel, user, queue)

        self.assertIn('or less', response)
        self.assertTrue(queue.empty())

    def testUnknownRequest(self):
        command = 'do something'
        channel = 'channel_id_string'
        user = 'user_id_string'
        queue = self.dummy_queue

        response = helpers.handle_command(command, channel, user, queue)

        self.assertIn('Not sure', response)
        self.assertTrue(queue.empty())

    def testValidScanRequest(self):
        command = 'scan 1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 5.5.5.5'
        channel = 'channel_id_string'
        user = 'user_id_string'
        queue = self.dummy_queue

        response = helpers.handle_command(command, channel, user, queue)

        self.assertIn('Scheduling', response)
        self.assertFalse(queue.empty())

    def testInvalidRequest(self):
        command = 'scan something'
        channel = 'channel_id_string'
        user = 'user_id_string'
        queue = self.dummy_queue

        response = helpers.handle_command(command, channel, user, queue)

        self.assertIn('like to', response)
        self.assertTrue(queue.empty())


def main():
    unittest.main()


if __name__ == '__main__':
    main()
